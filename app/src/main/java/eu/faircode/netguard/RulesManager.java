package eu.faircode.netguard;

// HeartGuard code - get and process rules from SQL, make decisions
public class RulesManager {

    private static RulesManager global_rm = null;

    public static RulesManager getInstance() {
        if (global_rm == null) {
            global_rm = new RulesManager();
        }
        return global_rm;
    }

    public RulesManager() {
    }

    public void getCurrentRules(WhitelistManager wm) {
        wm.addGlobalRule(new DomainRule("pluckeye.net", 1));
        wm.addGlobalRule(new IPRule("192.168.0.8", 1));
        wm.addGlobalRule(new IPRule("192.168.0.29", 1));
        wm.addAppRule(12, new IPRule("192.168.0.29", 1));
    }
}
