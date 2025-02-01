package heartguard.heartguard.main;

import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.util.Log;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class RuleAllowData {
    String ruletext;
    String input_daddr;
    String relevant_daddr;
    int allowed;
}

interface RuleForApp {
    RuleAllowData isAllowed(String daddr, List<String> dnames);
    boolean matchesAddr(String dname);
    String getRuletext();
}

// AKA an Allow rule that specifies a host or ipv4, and may or may not specify a package
// The package may be unspecified (UID_GLOBAL) or may not exist (UID_NOT_FOUND)
// Contains a RuleForApp which either matches domain names or IP addresses
class RuleAndPackage extends MyRule {
    public final static int UID_GLOBAL = -1;
    public final static int UID_NOT_FOUND = -2;

    public RuleForApp rule;
    private boolean m_sticky;
    private String m_packagename;
    private int m_uid;

    RuleAndPackage(String ruletext, Context context, RuleForApp rule, boolean sticky, String packagename) {
        super(ruletext, MAJOR_CATEGORY_ALLOW);
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

    public String getPackageName() {
        return m_packagename;
    }

    public int getUid() {
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

    @Override
    public Set<String> getActionsAfterAdd(Context context) {
        // After an add, the access rules that this matches will be allowed
        Set<Integer> uids_to_reload = WhitelistManager.getInstance(context).writeAccessRulesForAddition(context, this, false, 0);

        Set<String> actions = new HashSet<>();
        for (int uid : uids_to_reload) {
            actions.add("uid " + uid);
        }
        return actions;
    }

    @Override
    public Set<String> getActionsAfterRemove(Context context) {
        // After a delete, the access rules that this matches will be deleted
        // If they are allowed by another rule, let them be added again later.
        Set<Integer> uids_to_reload = WhitelistManager.getInstance(context).writeAccessRulesForAddition(context, this, true, 0);

        Set<String> actions = new HashSet<>();
        for (int uid : uids_to_reload) {
            actions.add("uid " + uid);
        }
        return actions;
    }
}

class DomainRule implements RuleForApp {
    private String domain;
    private int allowed;
    private String m_ruletext;

    DomainRule(String ruletext, String domain, int allowed) {
        this.domain = domain;
        this.allowed = allowed;
        this.m_ruletext = ruletext;
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

    public RuleAllowData isAllowed(String daddr, List<String> dnames) {
        for (String dname : dnames) {
            if (matchesAddr(dname)) {
                RuleAllowData result = new RuleAllowData();
                result.ruletext = this.m_ruletext;
                result.allowed = this.allowed;
                result.input_daddr = daddr;
                result.relevant_daddr = dname;
                return result;
            }
        }
        if (matchesAddr(daddr)) {
            RuleAllowData result = new RuleAllowData();
            result.ruletext = this.m_ruletext;
            result.allowed = this.allowed;
            result.input_daddr = daddr;
            result.relevant_daddr = daddr;
            return result;
        }
        return null;
    }

    public String getRuletext() {
        return m_ruletext;
    }
}

class IPRule implements RuleForApp {
    private static final String TAG = "Netguard.IPRule";
    private static int TYPE_SINGLE = 0;
    private static int TYPE_IPV4_SUBNET = 1;

    private String m_ip;
    private int m_allowed;
    private int m_subnet_ip;
    private int m_subnetmask;
    private int m_type;
    private String m_ruletext;

    IPRule(String ruletext, String ip, int allowed) {
        m_ip = ip;
        m_allowed = allowed;
        m_type = TYPE_SINGLE;
        m_ruletext = ruletext;

        try {
            Matcher m = Pattern.compile("(\\d+.\\d+.\\d+.\\d+)/(\\d+)").matcher(ip);
            if (m.matches()) {
                long numeric_ip = stringToIp(m.group(1));
                int subnetbits = Integer.parseInt(m.group(2));

                boolean valid = true;
                if (numeric_ip == -1)
                    valid = false;
                if ((subnetbits > 31) || (subnetbits < 1))
                    valid = false;

                if (valid) {
                    m_subnetmask = ~((1 << (32 - subnetbits)) - 1);
                    m_subnet_ip = ((int)numeric_ip) & m_subnetmask;
                    m_type = TYPE_IPV4_SUBNET;
                }
            }
        } catch (NumberFormatException e) {
        }
    }

    private static long stringToIp(String string) {
        Matcher m = Pattern.compile("(\\d+).(\\d+).(\\d+).(\\d+)").matcher(string);
        if (!m.matches()) {
            return -1;
        }

        long ip = 0;
        for (int i = 0; i < 4; i++) {
            ip = ip << 8;
            int thisbyte = Integer.parseInt(m.group(i+1));
            if ((thisbyte < 0) || (thisbyte > 255)) {
                return -1;
            }
            ip |= thisbyte;
        }

        return ip;
    }

    public RuleAllowData isAllowed(String daddr, List<String> dnames) {
        if (matchesAddr(daddr)) {
            RuleAllowData result = new RuleAllowData();
            result.ruletext = this.m_ruletext;
            result.allowed = this.m_allowed;
            result.input_daddr = daddr;
            result.relevant_daddr = this.m_ip;
            return result;
        }
        return null;
    }

    public boolean matchesAddr(String dname) {
        // TODO: better way to match?
        // TODO: IPV6? IPV6 subnets?
        if (m_type == TYPE_SINGLE) {
            if (dname.equals(this.m_ip))
                return true;
            return false;
        } else if (m_type == TYPE_IPV4_SUBNET) {
            long longip = stringToIp(dname);
            if (longip == -1) {
                return false;
            }
            int ip = (int)longip;
            if ((ip & m_subnetmask) == m_subnet_ip) {
                return true;
            }
            return false;
        } else {
            Log.e(TAG, "Unknown type");
            return false;
        }
    }

    public String getRuletext() {
        return m_ruletext;
    }
}

class DirectIPRule implements RuleForApp {
    String m_ruletext;
    DirectIPRule(String ruletext) {
        m_ruletext = ruletext;
    }

    public RuleAllowData isAllowed(String daddr, List<String> dnames) {
        if (!dnames.isEmpty()) {
            return null;
        }
        if (matchesAddr(daddr)) {
            RuleAllowData result = new RuleAllowData();
            result.ruletext = this.m_ruletext;
            result.allowed = 1;
            result.input_daddr = daddr;
            result.relevant_daddr = daddr;
            return result;
        }
        return null;
    }

    public boolean matchesAddr(String dname) {
        if (dname.matches("\\d+\\.\\d+\\.\\d+\\.\\d+") || dname.matches("[0-9a-fA-F:]+")) {
            return true;
        }
        return false;
    }

    public String getRuletext() {
        return m_ruletext;
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
                int uid = ruleandpackage.getUid();
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

        updateAllPendingFlags(context);
    }

    public RuleAllowData isAllowed(Context context, String daddr, int uid) {
        lock.readLock().lock();

        List<String> alldnames = new LinkedList<>();
        try (Cursor cursor = DatabaseHelper.getInstance(context).getAllQNames(daddr)) {
            while (cursor.moveToNext()) {
                alldnames.add(cursor.getString(0));
            }
        }
        try {
            // TODO: common code for both loops
            List<RuleForApp> rules = this.app_specific_rules.get(uid);
            if (rules != null) {
                for (RuleForApp rule : rules) {
                    RuleAllowData result = rule.isAllowed(daddr, alldnames);
                    if (result != null && result.allowed == 1) {
                        return result;
                    }
                }
            }

            rules = this.global_rules;
            for (RuleForApp rule : rules) {
                RuleAllowData result = rule.isAllowed(daddr, alldnames);
                if (result != null && result.allowed == 1) {
                    return result;
                }
            }

            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    public RuleAllowData isPendingAllowed(Context context, String daddr, int uid) {
        lock.readLock().lock();

        List<String> alldnames = new LinkedList<>();
        try (Cursor cursor = DatabaseHelper.getInstance(context).getAllQNames(daddr)) {
            while (cursor.moveToNext()) {
                alldnames.add(cursor.getString(0));
            }
        }
        try {
            // TODO: common code for both loops
            RulesManager rm = RulesManager.getInstance(context);
            List<RuleAndPackage> rules = rm.getPendingRules();
            for (RuleAndPackage rule : rules)
            {
                if ((rule.getUid() != RuleAndPackage.UID_GLOBAL) &&
                    (rule.getUid() != uid))
                {
                    // does not apply
                    continue;
                }
                RuleAllowData result = rule.rule.isAllowed(daddr, alldnames);
                if (result != null && result.allowed == 1) {
                    return result;
                }
            }

            return null;
        } finally {
            lock.readLock().unlock();
        }
    }

    public void updateAllPendingFlags(Context context) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);

        try (Cursor cursor = dh.getAllAccess()) {

            int col_id = cursor.getColumnIndexOrThrow("ID");
            int col_uid = cursor.getColumnIndexOrThrow("uid");
            int col_daddr = cursor.getColumnIndexOrThrow("daddr");
            //int col_block = cursor.getColumnIndexOrThrow("block");
            int col_allowed = cursor.getColumnIndexOrThrow("allowed");
            int col_pending = cursor.getColumnIndexOrThrow("pending_allow");

            while (cursor.moveToNext()) {
                int allow = cursor.getInt(col_allowed);
                if (allow > 0)
                    continue;
                int uid = cursor.getInt(col_uid);
                String daddr = cursor.getString(col_daddr);
                RuleAllowData result = isPendingAllowed(context, daddr, uid);
                int pending = 0;
                if (result != null && result.allowed == 1) {
                    pending = 1;
                }
                if (pending != cursor.getInt(col_pending)) {
                    dh.setAccessPending(Long.toString(cursor.getLong(col_id)), pending);
                }
            }
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

    public Set<Integer> writeAccessRulesForAddition(Context context, RuleAndPackage addedrule, boolean delete, int block) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);

        try (Cursor cursor = dh.getAllAccess()) {

            int col_id = cursor.getColumnIndexOrThrow("ID");
            int col_uid = cursor.getColumnIndexOrThrow("uid");
            int col_daddr = cursor.getColumnIndexOrThrow("daddr");
            int col_block = cursor.getColumnIndexOrThrow("block");

            Set<Integer> uids_to_reload = new HashSet<>();

            while (cursor.moveToNext()) {
                int uid = cursor.getInt(col_uid);

                // Check if UID matches or is global
                int rule_uid = addedrule.getUid();
                if (rule_uid == RuleAndPackage.UID_NOT_FOUND) {
                    // The package doesn't exist, so, no access rules must match
                    continue;
                }
                if ((rule_uid != RuleAndPackage.UID_GLOBAL) && (rule_uid != uid)) {
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
                    if (delete) {
                        Log.w(TAG, String.format("Clearing access ID %d because uid %d daddr %s is a match", id, uid, match));
                        dh.clearAccessId(id);
                        uids_to_reload.add(uid);
                    } else {
                        int access_block = cursor.getInt(col_block);

                        if (access_block != block) {
                            Log.w(TAG, String.format("Setting access ID %d to %d because uid %d daddr %s is a match", id, block, uid, match));
                            RuleAllowData ruleAllowData;
                            if (block == 0)
                            {
                                ruleAllowData = new RuleAllowData();
                                ruleAllowData.ruletext = addedrule.rule.getRuletext();
                                ruleAllowData.allowed = 1;
                                ruleAllowData.input_daddr = daddr;
                                ruleAllowData.relevant_daddr = match;
                            } else {
                                ruleAllowData = null;
                            }
                            dh.setAccess(id, ruleAllowData, "writeAccessRulesForAddition, rule_uid = " + rule_uid);
                            uids_to_reload.add(uid);
                        }
                    }
                }
            }

            return uids_to_reload;
        }
    }
}
