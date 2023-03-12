package eu.faircode.netguard;

import android.content.Context;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

interface RuleForApp {
    int isAllowed(Packet packet, String dname);
}

class RuleAndUid {
    public final static int UID_GLOBAL = 0;

    public int uid;
    public RuleForApp rule;

    RuleAndUid(int uid, RuleForApp rule) {
        this.uid = uid;
        this.rule = rule;
    }
}

class DomainRule implements RuleForApp {
    private String domain;
    private int allowed;

    DomainRule(String domain, int allowed) {
        this.domain = domain;
        this.allowed = allowed;
    }

    public int isAllowed(Packet packet, String dname) {
        if (dname == null)
            return -1;
        if (dname.endsWith(this.domain))
            return this.allowed;
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

    public int isAllowed(Packet packet, String dname) {
        // TODO: allow IP address block allowing
        // TODO: better way to match?
        // TODO: IPV6?
        if (packet.daddr.equals(this.ip))
            return this.allowed;
        return -1;
    }
}

// HeartGuard code - decide based on existing rules whether to allow a site
public class WhitelistManager {

    private Map<Integer, List<RuleForApp>> app_specific_rules;
    private List<RuleForApp> global_rules;

    private static WhitelistManager global_wm = null;

    public static WhitelistManager getInstance(Context context) {
        if (global_wm == null) {
            global_wm = new WhitelistManager(context);
        }
        return global_wm;
    }

    public WhitelistManager(Context context) {
        this.app_specific_rules = new HashMap<>();
        this.global_rules = new LinkedList<>();

        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        RulesManager rm = RulesManager.getInstance(context);
        rm.getCurrentRules(this, dh);
    }

    public boolean isAllowed(Packet packet, String dname) {
        // TODO: common code for both loops
        // TODO: make sure domain is a whole word
        List<RuleForApp> rules = this.app_specific_rules.get(packet.uid);
        if (rules != null) {
            for (RuleForApp rule : rules) {
                int allowed = rule.isAllowed(packet, dname);
                if (allowed >= 0)
                    return allowed == 1;
            }
        }

        rules = this.global_rules;
        for (RuleForApp rule : rules) {
            int allowed = rule.isAllowed(packet, dname);
            if (allowed >= 0)
                return allowed == 1;
        }

        return false;
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
}
