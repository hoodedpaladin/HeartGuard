package eu.faircode.netguard;

import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.util.Log;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

interface RuleForApp {
    int isAllowed(Packet packet, List<String> dnames);
    boolean matchesAddr(String dname);
}

// AKA an Allow rule that specifies a host or ipv4, and may or may not specify a package
// The package may be unspecified (UID_GLOBAL) or may not exist (UID_NOT_FOUND)
// Contains a RuleForApp which either matches domain names or IP addresses
class RuleAndPackage implements RuleWithDelayClassification {
    public final static int UID_GLOBAL = -1;
    public final static int UID_NOT_FOUND = -2;

    public RuleForApp rule;
    private boolean m_sticky;
    private String m_packagename;
    private int m_uid;

    RuleAndPackage(Context context, RuleForApp rule, boolean sticky, String packagename) {
        this.rule = rule;
        m_sticky = sticky;
        m_packagename = packagename;
        m_uid = getUidForPackageName(context, m_packagename);
    }

    public int getDelayToAdd(Context context, int main_delay) {
        // The RulesManager may have a shortened delay for this package
        if (m_packagename != null) {
            RulesManager rm = RulesManager.getInstance(context);
            int specific_delay = rm.getSpecificDelayForPackage(m_packagename);
            if (specific_delay < main_delay) {
                return specific_delay;
            }
        }
        return main_delay;
    }
    public int getDelayToRemove(Context context, int main_delay) {
        if (m_sticky) {
            return main_delay;
        } else {
            return 0;
        }
    }

    public int getMajorCategory() {
        return UniversalRule.MAJOR_CATEGORY_ALLOW;
    }

    public int getMinorCategory() {
        return 0;
    }

    public String getPackageName() {
        return m_packagename;
    }

    public int getUid(Context context) {
        return m_uid;
    }

    // Static helper function to look up a UID
    // Can return UID_GLOBAL for non-package specific or UID_NOT_FOUND for UID not found
    private static int getUidForPackageName(Context context, String packageName) {
        if ((packageName == null) || (packageName == "")) {
            return UID_GLOBAL;
        }
        try {
            return context.getPackageManager().getApplicationInfo(packageName, 0).uid;
        } catch (PackageManager.NameNotFoundException e) {
            return UID_NOT_FOUND;
        }
    }

    // Handy method to check whether something applies to an access rule
    public boolean appliesToAccess(int uid, List<String> daddrs) {
        if (m_uid != UID_GLOBAL) {
            if (m_uid != uid) {
                return false;
            }
        }

        for (String daddr : daddrs) {
            if (rule.matchesAddr(daddr)) {
                return true;
            }
        }

        return false;
    }
}

class DomainRule implements RuleForApp {
    private String domain;
    private int allowed;

    DomainRule(String domain, int allowed) {
        this.domain = domain;
        this.allowed = allowed;
    }

    public boolean matchesAddr(String dname) {
        if (dname == null) {
            return false;
        }
        if (dname.equals(this.domain))
            return true;
        if (dname.endsWith("." + this.domain))
            return true;
        return false;
    }

    public int isAllowed(Packet packet, List<String> dnames) {
        for (String dname : dnames) {
            if (matchesAddr(dname)) {
                return this.allowed;
            }
        }
        return -1;
    }
}

class IPRule implements RuleForApp {
    private String ip;
    private int allowed;

    IPRule(String ip, int allowed) {
        this.ip = ip;
        this.allowed = allowed;
    }

    public int isAllowed(Packet packet, List<String> dnames) {
        if (matchesAddr(packet.daddr))
            return this.allowed;
        return -1;
    }

    public boolean matchesAddr(String dname) {
        // TODO: allow IP address block allowing
        // TODO: better way to match?
        // TODO: IPV6?
        if (dname.equals(this.ip))
            return true;
        return false;
    }
}

// HeartGuard code - decide based on existing rules whether to allow a site
public class WhitelistManager {
    private static final String TAG = "NetGuard.WM";

    private Map<Integer, List<RuleForApp>> app_specific_rules;
    private List<RuleForApp> global_rules;

    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    private static WhitelistManager global_wm = null;

    public static WhitelistManager getInstance(Context context) {
        if (global_wm == null) {
            global_wm = new WhitelistManager(context);
        }
        return global_wm;
    }

    public WhitelistManager(Context context) {
        updateRulesFromRulesManager(context);
    }

    public void updateRulesFromRulesManager(Context context) {
        lock.writeLock().lock();

        try {
            this.app_specific_rules = new HashMap<>();
            this.global_rules = new LinkedList<>();

            RulesManager rm = RulesManager.getInstance(context);
            List<RuleAndPackage> ruleslist = rm.getCurrentRules(context);

            for (RuleAndPackage ruleandpackage : ruleslist) {
                int uid = ruleandpackage.getUid(context);
                if (uid == RuleAndPackage.UID_GLOBAL) {
                    addGlobalRule(ruleandpackage.rule);
                } else if (uid == RuleAndPackage.UID_NOT_FOUND) {
                    // No package found, so no whitelisting right now
                }else {
                    addAppRule(uid, ruleandpackage.rule);
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public boolean isAllowed(Context context, Packet packet, String dname) {
        lock.readLock().lock();

        List<String> alldnames = new LinkedList<>();
        Cursor cursor = DatabaseHelper.getInstance(context).getAllQNames(packet.daddr);
        while (cursor.moveToNext()) {
            alldnames.add(cursor.getString(0));
        }
        try {
            // TODO: common code for both loops
            // TODO: make sure domain is a whole word
            List<RuleForApp> rules = this.app_specific_rules.get(packet.uid);
            if (rules != null) {
                for (RuleForApp rule : rules) {
                    int allowed = rule.isAllowed(packet, alldnames);
                    if (allowed >= 0)
                        return allowed == 1;
                }
            }

            rules = this.global_rules;
            for (RuleForApp rule : rules) {
                int allowed = rule.isAllowed(packet, alldnames);
                if (allowed >= 0)
                    return allowed == 1;
            }

            return false;
        } finally {
            lock.readLock().unlock();
        }
    }

    public void addGlobalRule(RuleForApp rule) {
        this.global_rules.add(rule);
    }

    public void addAppRule(int uid, RuleForApp rule) {
        if (!this.app_specific_rules.containsKey(uid)) {
            this.app_specific_rules.put(uid, new LinkedList<RuleForApp>());
        }
        List<RuleForApp> list = this.app_specific_rules.get(uid);
        list.add(rule);
    }

    public void clearAccessRulesForAddition(Context context, RuleAndPackage addedrule) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);

        Cursor cursor = dh.getAllAccess();

        int col_id = cursor.getColumnIndexOrThrow("ID");
        int col_uid = cursor.getColumnIndexOrThrow("uid");
        int col_daddr = cursor.getColumnIndexOrThrow("daddr");

        boolean reload = false;
        while (cursor.moveToNext()) {
            int uid = cursor.getInt(col_uid);

            // Check if UID matches or is global
            int rule_uid = addedrule.getUid(context);
            if (rule_uid == RuleAndPackage.UID_NOT_FOUND) {
                // The package doesn't exist, so, no access rules must match
                continue;
            }
            if ((rule_uid != RuleAndPackage.UID_GLOBAL) && (uid != uid)) {
                continue;
            }

            // Get a list of all applicable dnames
            String daddr = cursor.getString(col_daddr);
            List<String> alldnames = dh.getListAlternateQNames(daddr);

            String match = null;
            for (String thisdname : alldnames) {
                if (addedrule.rule.matchesAddr(thisdname)) {
                    match = thisdname;
                    break;
                }
            }

            if (match != null) {
                long id = cursor.getLong(col_id);
                Log.w(TAG, String.format("Clearing access ID %d because uid %d daddr %s is a match", id, uid, match));
                dh.clearAccessId(id);
                reload = true;
            }
        }

        if (reload) {
            ServiceSinkhole.reload("access changed", context, false);
        }
    }
}
