package eu.faircode.netguard;

import android.app.Service;
import android.content.Context;
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

class RuleAndUid implements RuleWithDelayClassification {
    public final static int UID_GLOBAL = 0;

    public int uid;
    public RuleForApp rule;
    private boolean m_sticky;

    RuleAndUid(int uid, RuleForApp rule, boolean sticky) {
        this.uid = uid;
        this.rule = rule;
        m_sticky = sticky;
    }

    public Classification getClassification() {
        return Classification.delay_normal;
    }
    public Classification getClassificationToRemove() {
        if (m_sticky) {
            return Classification.delay_normal;
        } else {
            return Classification.delay_free;
        }
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
            List<RuleAndUid> ruleslist = rm.getCurrentRules(context);

            for (RuleAndUid ruleanduid : ruleslist) {
                if (ruleanduid.uid == RuleAndUid.UID_GLOBAL) {
                    addGlobalRule(ruleanduid.rule);
                } else {
                    addAppRule(ruleanduid.uid, ruleanduid.rule);
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

    public void clearAccessRulesForAddition(Context context, RuleAndUid addedrule) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);

        Cursor cursor = dh.getAllAccess();

        int col_id = cursor.getColumnIndexOrThrow("ID");
        int col_uid = cursor.getColumnIndexOrThrow("uid");
        int col_daddr = cursor.getColumnIndexOrThrow("daddr");

        boolean reload = false;
        while (cursor.moveToNext()) {
            int uid = cursor.getInt(col_uid);

            // Check if UID matches or is global
            if ((addedrule.uid != RuleAndUid.UID_GLOBAL) && (addedrule.uid != uid)) {
                continue;
            }

            String daddr = cursor.getString(col_daddr);
            List<String> alldnames = new LinkedList<>();
            alldnames.add(daddr);
            Cursor alternates_cursor = dh.getAlternateQNames(daddr);
            while (alternates_cursor.moveToNext()) {
                alldnames.add(alternates_cursor.getString(0));
            }

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
