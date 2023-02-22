package eu.faircode.netguard;

import android.database.Cursor;
import android.util.Log;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

// HeartGuard code - get and process rules from SQL, make decisions
public class RulesManager {
    private static final String TAG = "NetGuard.Database";

    private static RulesManager global_rm = null;

    public static RulesManager getInstance() {
        if (global_rm == null) {
            global_rm = new RulesManager();
        }
        return global_rm;
    }

    public RulesManager() {
    }

    private RuleAndUid parseTextToWhitelistRule(String text) {
        Pattern p = Pattern.compile("allow (.*)");
        Matcher m = p.matcher(text);
        if (!m.matches())
            return null;
        String constraints = m.group(1);

        int uid = 0;
        RuleForApp rule = null;
        String[] separated = constraints.split(" ");
        for (String phrase : separated) {
            m = Pattern.compile("packagename:(.*)").matcher(phrase);
            if (m.matches()) {
                // TODO: implement package name -> UID
                Log.e(TAG, "not implemented!");
            }

            m = Pattern.compile("host:(.+)").matcher(phrase);
            if (m.matches()) {
                assert rule == null;
                rule = new DomainRule(m.group(1), 1);
            }

            m = Pattern.compile("ipv4:(.+)").matcher(phrase);
            if (m.matches()) {
                assert rule == null;
                rule = new IPRule(m.group(1), 1);
            }
        }

        if (rule == null)
            return null;

        return new RuleAndUid(uid, rule);
    }

    public void getCurrentRules(WhitelistManager wm, DatabaseHelper dh) {
        Cursor cursor = dh.getEnactedRules();
        int col_ruletext = cursor.getColumnIndexOrThrow("ruletext");

        while (cursor.moveToNext()) {
            String ruletext = cursor.getString(col_ruletext);

            RuleAndUid ruleanduid = parseTextToWhitelistRule(ruletext);
            if (ruleanduid == null)
                continue;
            if (ruleanduid.uid == RuleAndUid.UID_GLOBAL) {
                wm.addGlobalRule(ruleanduid.rule);
            } else {
                wm.addAppRule(ruleanduid.uid, ruleanduid.rule);
            }
        }
    }
}
