package eu.faircode.netguard;

import static java.lang.Math.max;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import androidx.annotation.GuardedBy;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import androidx.preference.PreferenceManager;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// HeartGuard code - get and process rules from SQL, make decisions
public class RulesManager {
    private static final String TAG = "NetGuard.RulesManager";

    public static final String ACTION_RULES_UPDATE = "eu.faircode.netguard.RULES_UPDATE";

    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    private static volatile RulesManager global_rm = null;

    // Members that contain the current state of rules
    // m_allCurrentRules being the master list, and the rest of these should
    // always be updated based on its contents
    private List<UniversalRule> m_allCurrentRules = new ArrayList<UniversalRule>();
    private boolean m_enabled = true;
    private int m_delay = 0;
    private Map<String, Boolean> m_allowedPackages;

    private long next_pending_time = 0;

    private ExecutorService executor = Executors.newCachedThreadPool();

    public static RulesManager getInstance(Context context) {
        if (global_rm == null) {
            // Synchronize so that definitely only one instance is created
            synchronized(RulesManager.class) {
                if (global_rm == null) {
                    global_rm = new RulesManager(context.getApplicationContext());
                }
            }
        }
        return global_rm;
    }

    public RulesManager(Context context) {
        long curr_time = System.currentTimeMillis();

        // Now parse all rules
        // (Do this before any other logical steps, just in case we logically need the
        // current rules for our decisions.)
        getAllEnactedRulesFromDb(context);

        // Activate rules that took effect while we were asleep
        // But don't send change notifications, because we are just starting up
        activateRulesUpTo(context, curr_time, true);

        // We want an alarm for any pending rules
        setAlarmForPending(context);
    }

    // Convenience functions to throw exceptions if a rule uses the same phrase twice
    public static void putNewInt(Bundle bundle, String key, int value) {
        if (bundle.containsKey(key)) {
            throw new AssertionError("Already contains key " + key);
        }
        bundle.putInt(key, value);
    }
    public static void putNewString(Bundle bundle, String key, String value) {
        if (bundle.containsKey(key)) {
            throw new AssertionError("Already contains key " + key);
        }
        bundle.putString(key, value);
    }

    // Somewhat general function to parse an allow rule into a bundle of all phrases
    public static Bundle parseAllowTextToBundle(Context context, String text) {
        Bundle data_bundle = new Bundle();

        Pattern p = Pattern.compile("allow (.*)");
        Matcher m = p.matcher(text);
        if (!m.matches())
            return null;
        String constraints = m.group(1);

        String[] separated = constraints.split(" ");

        for (String phrase : separated) {
            m = Pattern.compile("package:(.*)").matcher(phrase);
            if (m.matches()) {
                String packagename = m.group(1);
                try {
                    int uid = context.getPackageManager().getApplicationInfo(packagename, 0).uid;
                    putNewInt(data_bundle, "uid", uid);
                    putNewString(data_bundle, "package", packagename);
                } catch (PackageManager.NameNotFoundException e) {
                    Log.w(TAG, "package " + packagename + " not found");
                    return null;
                }

                // Done parsing this phrase
                continue;
            }

            m = Pattern.compile("host:(.+)").matcher(phrase);
            if (m.matches()) {
                putNewString(data_bundle, "host", m.group(1));

                // Done parsing this phrase
                continue;
            }

            m = Pattern.compile("ipv4:(.+)").matcher(phrase);
            if (m.matches()) {
                putNewString(data_bundle, "ipv4", m.group(1));

                // Done parsing this phrase
                continue;
            }

            throw new AssertionError("\"" + phrase + "\" didn't contain any recognized phrases");
        }

        return data_bundle;
    }

    // Returns a RuleAndUid for whitelist rules
    // (Only applies to a rule which allows a hostname/IP and optionally a package name.
    // Does not apply to rules which enable a package unconditionally.)
    public static RuleAndUid parseTextToWhitelistRule(Context context, String text) {
        Bundle data_bundle = parseAllowTextToBundle(context, text);

        if (data_bundle == null)
            return null;

        int uid = 0;
        if (data_bundle.containsKey("uid")) {
            uid = data_bundle.getInt("uid");
        }

        if (data_bundle.containsKey("host"))
        {
            if (data_bundle.containsKey("ipv4")) {
                Log.e(TAG, "Rule string " + text + " has invalid combination of types");
                return null;
            }
            return new RuleAndUid(uid, new DomainRule(data_bundle.getString("host"), 1));
        }

        if (data_bundle.containsKey("ipv4"))
        {
            if (data_bundle.containsKey("host")) {
                Log.e(TAG, "Rule string " + text + " has invalid combination of types");
                return null;
            }
            return new RuleAndUid(uid, new IPRule(data_bundle.getString("ipv4"), 1));
        }

        // No rule found
        return null;
    }

    // Give a copy of the current whitelist rules
    public List<RuleAndUid> getCurrentRules(Context context) {
        lock.readLock().lock();
        List<RuleAndUid> results = new ArrayList<RuleAndUid>();

        for (UniversalRule rule : m_allCurrentRules) {
            if (rule.type == RuleAndUid.class) {
                results.add((RuleAndUid)rule.rule);
            }
        }
        lock.readLock().unlock();

        return results;
    }

    public boolean getPreferenceFilter(Context context) {
        return true;
    }

    public boolean getPreferenceEnabled(Context context) {
        return m_enabled;
    }

    public boolean getPreferenceLogApp(Context context) {
        return true;
    }

    public boolean getPreferenceScreenOnWifi(Context context) {
        return false;
    }

    public boolean getPreferenceScreenOnOther(Context context) {
        return false;
    }

    public boolean getPreferenceScreenOn(Context context) {
        return false;
    }

    // "whitelist_wifi", when true, blocks apps on wifi. Nomenclature skills ???
    public boolean getPreferenceWhitelistWifi(Context context) {
        return true;
    }

    // "whitelist_wifi", when true, blocks apps on other. Nomenclature skills ???
    public boolean getPreferenceWhitelistOther(Context context) {
        return true;
    }

    public boolean getPreferenceLockdown(Context context) {
        return false;
    }

    public boolean getPreferenceLockdownWifi(Context context) {
        return false;
    }

    public boolean getPreferenceLockdownOther(Context context) {
        return false;
    }

    public boolean getPreferenceWhitelistRoaming(Context context) {
        return false;
    }

    public boolean getWifiEnabledForApp(Context context, String packagename, boolean defaultVal) {
        if (m_allowedPackages.containsKey(packagename)) {
            return m_allowedPackages.get(packagename);
        }
        return defaultVal;
    }
    public boolean getOtherEnabledForApp(Context context, String packagename, boolean defaultVal) {
        // Identical settings to above
        return getWifiEnabledForApp(context, packagename, defaultVal);
    }
    public boolean getScreenWifiEnabledForApp(Context context, String packagename, boolean defaultVal) {
        // Identical settings to above
        return getWifiEnabledForApp(context, packagename, defaultVal);
    }
    public boolean getScreenOtherEnabledForApp(Context context, String packagename, boolean defaultVal) {
        // Identical settings to above
        return getWifiEnabledForApp(context, packagename, defaultVal);
    }

    private void setAlarmForTime(Context context, long time) {
        AlarmManager am = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
        Intent i = new Intent(context, ServiceSinkhole.class);
        i.setAction(ACTION_RULES_UPDATE);
        PendingIntent pi;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            pi = PendingIntent.getForegroundService(context, 1, i, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);
        else
            pi = PendingIntent.getService(context, 1, i, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE);
        am.cancel(pi);

        am.set(AlarmManager.RTC_WAKEUP, time, pi);
    }

    private void setAlarmForPending(Context context) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        Cursor cursor = dh.getPendingRules();

        if (!cursor.moveToFirst()) {
            // No pending rules
            return;
        }

        int col_ruletext = cursor.getColumnIndexOrThrow("ruletext");
        int col_id = cursor.getColumnIndexOrThrow("ID");
        int col_enact_time = cursor.getColumnIndexOrThrow("enact_time");

        String ruletext = cursor.getString(col_ruletext);
        long id = cursor.getLong(col_id);
        long enact_time = cursor.getLong(col_enact_time);

        Log.w(TAG, "Pending rule \"" + ruletext + "\" ID=" + Long.toString(id) + " enact_time=" + Long.toString(enact_time));

        // For comparison later when we get the alarm
        next_pending_time = enact_time;

        setAlarmForTime(context, enact_time);
    }

    // Activate all rules up to a certain time.
    // Upon initial object creation, set startup=true, and we will not reload rules / alert listeners
    private void activateRulesUpTo(Context context, long current_time, boolean startup) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        Cursor cursor = dh.getPendingRules();

        int col_ruletext = cursor.getColumnIndexOrThrow("ruletext");
        int col_id = cursor.getColumnIndexOrThrow("ID");
        int col_enact_time = cursor.getColumnIndexOrThrow("enact_time");

        int num_enacted = 0;
        while (cursor.moveToNext()) {
            String ruletext = cursor.getString(col_ruletext);
            long id = cursor.getLong(col_id);
            long enact_time = cursor.getLong(col_enact_time);

            Log.d(TAG, "Pending rule \"" + ruletext + "\" ID=" + Long.toString(id) + " enact_time=" + Long.toString(enact_time));

            if (enact_time > current_time) {
                break;
            }
            boolean changed = enactRule(context, ruletext, id);
            if (changed) {
                num_enacted += 1;
            }
            logAllRuleDbEntries(context, "just enacted a rule");
        }

        if (num_enacted > 0) {
            getAllEnactedRulesFromDb(context);
            WhitelistManager.getInstance(context).updateRulesFromRulesManager(context);
            if (!startup) {
                LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent(ActivityMain.ACTION_RULES_CHANGED));
            }
            ServiceSinkhole.reload("rule changed", context, false);
        }
    }

    // Sets a row to enacted. Returns true if this makes a runtime change.
    private boolean enactRule(Context context, String ruletext, long id) {
        Log.w(TAG, "Enacting rule \"" + ruletext + "\" ID=" + Long.toString(id));

        if (ruletext.startsWith("- ")) {
            // This is a negative rule
            return enactNegativeRule(context, ruletext, id);
        }

        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        lock.writeLock().lock();
        try {
            dh.setRuleEnacted(Long.toString(id), 1);
        } finally {
            lock.writeLock().unlock();
        }

        UniversalRule rule = UniversalRule.getRuleFromText(context, ruletext);
        if (rule.type == RuleAndUid.class) {
            // Clear access rules for all relevant apps
            RuleAndUid ruleanduid = (RuleAndUid)rule.rule;
            WhitelistManager.getInstance(context).clearAccessRulesForAddition(context, ruleanduid);
        }

        return true;
    }

    private boolean enactNegativeRule(Context context, String ruletext, long id) {
        Matcher m = Pattern.compile("- (.*)").matcher(ruletext);

        if (!m.matches()) {
            throw new AssertionError("Thought this string was negative: " + ruletext);
        }

        String otherruletext = m.group(1);

        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        Cursor cursor = dh.getRuleMatchingRuletext(otherruletext);

        if (!cursor.moveToFirst()) {
            Log.w(TAG, String.format("Didn't find the positive rule for \"%s\"", ruletext));
            dh.removeRulesById(new Long[]{id});
            return false;
        }
        int col_id = cursor.getColumnIndexOrThrow("ID");
        int col_enacted = cursor.getColumnIndexOrThrow("enacted");

        boolean was_enacted = cursor.getInt(col_enacted) != 0;
        long otherid = cursor.getLong(col_id);

        Log.w(TAG, String.format("Removing IDs %d and %d due to deletion rule", id, otherid));
        dh.removeRulesById(new Long[]{id, otherid});

        // Check if access rules should be deleted
        UniversalRule rule = UniversalRule.getRuleFromText(context, otherruletext);
        if (rule.type == RuleAndUid.class) {
            // Clear access rules for all relevant apps
            RuleAndUid ruleanduid = (RuleAndUid)rule.rule;
            WhitelistManager.getInstance(context).clearAccessRulesForAddition(context, ruleanduid);
        }

        return was_enacted;
    }

    public void rulesChanged(Context context) {
        Long curr_time = System.currentTimeMillis();

        Log.w(TAG, "Got a rulesChanged update - next pending time was " +
                Long.toString(next_pending_time) + ", time is now " +
                Long.toString(curr_time));

        activateRulesUpTo(context, curr_time, false);
    }

    public void queueRuleText(Context context, String ruletext) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        int delay = m_delay;

        // Check for existing (enacted or pending) rule
        Cursor existing_rule = dh.getRuleMatchingRuletext(ruletext);
        if (existing_rule.moveToFirst()) {
            Log.w(TAG, String.format("Rule \"%s\" already exists", ruletext));
            return;
        }

        Matcher m = Pattern.compile("- (.*)").matcher(ruletext);

        if (m.matches()) {
            // This is a negative rule
            String ruletext_to_remove = m.group(1);

            // Not only do we not want a duplicate removal rule, we also don't want to
            // queue a removal for a rule that doesn't exist
            existing_rule = dh.getRuleMatchingRuletext(ruletext_to_remove);
            if (!existing_rule.moveToFirst()) {
                Log.w(TAG, String.format("Rule \"%s\" has nothing to delete", ruletext));
                return;
            }
            RuleWithDelayClassification.Classification remove_classification =
                    UniversalRule.getRuleFromText(context, ruletext_to_remove)
                            .rule.getClassificationToRemove();
            if (remove_classification == RuleWithDelayClassification.Classification.delay_free) {
                delay = 0;
            } else if (remove_classification == RuleWithDelayClassification.Classification.delay_depends) {
                throw new AssertionError(String.format("Don't know how to deal with this deletion \"%s\"", ruletext));
            }
        } else {
            // Parse to UniversalRule to get stats on it
            UniversalRule newrule = UniversalRule.getRuleFromText(context, ruletext);

            // Choose delay based on stats
            if (newrule.rule.getClassification() == RuleWithDelayClassification.Classification.delay_free) {
                delay = 0;
            }
            if (newrule.rule.getClassification() == RuleWithDelayClassification.Classification.delay_depends) {
                if (newrule.type == DelayRule.class) {
                    int other_delay = ((DelayRule) newrule.rule).getDelay();

                    if (other_delay > m_delay) {
                        delay = 0;
                    } else {
                        delay = m_delay - other_delay;
                    }
                }
            }
        }

        long curr_time = System.currentTimeMillis();
        long enact_time = curr_time + (delay * 1000L);
        Log.w(TAG, String.format("Queueing new rule \"%s\" with %d delay (enact_time %d)", ruletext, delay, enact_time));
        dh.addNewRule(ruletext, enact_time, 0);
        logAllRuleDbEntries(context, "just queued new rule");

        // Activate rules up to now, in case that was instantaneous
        activateRulesUpTo(context, curr_time, false);

        // Set a new alarm, in case it wasn't instantaneous
        setAlarmForPending(context);
    }

    public void setPackageAllowed(Context context, String packagename) {
        String ruletext = "allow package:" + packagename;

        if (m_allowedPackages.containsKey(packagename)) {
            ruletext = "- " + ruletext;
        }
        queueRuleText(context, ruletext);
    }

    private void getAllEnactedRulesFromDb(Context context) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);

        lock.writeLock().lock();

        Cursor cursor = dh.getEnactedRules();
        int col_ruletext = cursor.getColumnIndexOrThrow("ruletext");

        // Read all rules from DB into list
        List<UniversalRule> allrules = new ArrayList<UniversalRule>();
        while (cursor.moveToNext()) {
            String ruletext = cursor.getString(col_ruletext);
            allrules.add(UniversalRule.getRuleFromText(context, ruletext));
        }

        m_allCurrentRules = allrules;
        updateFieldsFromCurrentRules(context);

        Log.w(TAG, "Got " + Integer.toString(m_allCurrentRules.size()) + " rules from DB");

        lock.writeLock().unlock();
    }

    private void updateFieldsFromCurrentRules(Context context) {
        // If there are no delay rules, delay will be 0
        int newDelay = 0;
        boolean newEnabled = false;
        Map<String, Boolean> newAllowedPackages = new HashMap<>();

        logAllRuleDbEntries(context, "updateFieldsFromCurrentRules");

        for (UniversalRule rule : m_allCurrentRules) {
            if (rule.type == DelayRule.class) {
                newDelay = max(newDelay, ((DelayRule)rule.rule).getDelay());
            } else if (rule.type == FeatureRule.class) {
                String featureName = ((FeatureRule)rule.rule).getFeatureName();

                if ("enabled".equals(featureName)) {
                    newEnabled = true;
                }
            } else if (rule.type == AllowedPackageRule.class) {
                String packageName = ((AllowedPackageRule)rule.rule).getPackageName();

                // False = not filtered i.e. allowed
                newAllowedPackages.put(packageName, false);
            }
        }

        if (m_delay != newDelay) {
            m_delay = newDelay;
            Log.w(TAG, "Delay changed from " + Integer.toString(m_delay) + " to " + Integer.toString(newDelay));
        }
        if (m_enabled != newEnabled) {
            Log.w(TAG, "Enabled changed from " + Boolean.toString(m_enabled) + " to " + Boolean.toString(newEnabled));
            m_enabled = newEnabled;
        }
        m_allowedPackages = newAllowedPackages;
    }

    public static String getStringOfRuleDbEntry(Cursor cursor) {
        String message = "DB entry:";
        message += " ID=" + Long.toString(cursor.getLong(cursor.getColumnIndexOrThrow("ID")));
        message += " ruletext=\"" + cursor.getString(cursor.getColumnIndexOrThrow("ruletext")) + "\"";
        message += " create_time=" + Long.toString(cursor.getLong(cursor.getColumnIndexOrThrow("create_time")));
        message += " enact_time=" + Long.toString(cursor.getLong(cursor.getColumnIndexOrThrow("enact_time")));
        message += " enacted=" + Integer.toString(cursor.getInt(cursor.getColumnIndexOrThrow("enacted")));
        message += " major_category=" + Integer.toString(cursor.getInt(cursor.getColumnIndexOrThrow("major_category")));
        message += " minor_category=" + Integer.toString(cursor.getInt(cursor.getColumnIndexOrThrow("minor_category")));

        return message;
    }

    public static void logAllRuleDbEntries(Context context, String explanation) {
        Log.w(TAG, "Logging all rules DB entries at point of time \"" + explanation + "\"");

        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        Cursor cursor = dh.getAllRules();

        int i = 0;
        while (cursor.moveToNext()) {
            Log.w(TAG, Integer.toString(i) + ": " + getStringOfRuleDbEntry(cursor));
            i += 1;
        }
        Log.w(TAG, Integer.toString(i) + " total entries");
    }
}

interface RuleWithDelayClassification {
    public enum Classification {delay_free, delay_normal, delay_depends};

    public Classification getClassification();
    public Classification getClassificationToRemove();
}

class DelayRule implements RuleWithDelayClassification {
    private int m_delay;

    public DelayRule(int delay) {
        m_delay = delay;
    }

    public int getDelay() {
        return m_delay;
    }

    public Classification getClassification() {
        return Classification.delay_depends;
    }

    public Classification getClassificationToRemove() {
        return Classification.delay_depends;
    }
}

class AllowedPackageRule implements RuleWithDelayClassification {
    private String m_packagename;

    public AllowedPackageRule(String packagename) {
        m_packagename = packagename;
    }

    public String getPackageName() {
        return m_packagename;
    }

    public Classification getClassification() {
        return Classification.delay_normal;
    }
    public Classification getClassificationToRemove() {
        // TODO: sticky keyword will affect this
        return Classification.delay_free;
    }
}

class FeatureRule implements RuleWithDelayClassification {
    private String m_featurename;
    private enum FeatureType {feature_restrictive, feature_permissive};
    private FeatureType m_featuretype;

    private static FeatureType getClassificationForName(String featurename) {
        if ("enabled".equals(featurename)) {
            return FeatureType.feature_restrictive;
        }

        throw new AssertionError("feature name \"" + featurename + "\" not present");
    }

    public FeatureRule(String featurename) {
        m_featurename = featurename;
        m_featuretype = getClassificationForName(featurename);
    }

    public String getFeatureName() {
        return m_featurename;
    }

    public Classification getClassification() {
        if (m_featuretype == FeatureType.feature_restrictive) {
            return Classification.delay_free;
        } else if (m_featuretype == FeatureType.feature_permissive) {
            return Classification.delay_normal;
        } else {
            throw new AssertionError("Problem here");
        }
    }

    public Classification getClassificationToRemove() {
        if (m_featuretype == FeatureType.feature_restrictive) {
            return Classification.delay_normal;
        } else if (m_featuretype == FeatureType.feature_permissive) {
            return Classification.delay_free;
        } else {
            throw new AssertionError("Problem here");
        }
    }
}

class UniversalRule {
    private static final String TAG = "NetGuard.UniversalRule";

    public RuleWithDelayClassification rule;
    public Class type;
    private String m_ruletext;

    public UniversalRule(RuleAndUid ruleanduid, String ruletext) {
        rule = ruleanduid;
        type = RuleAndUid.class;
        m_ruletext = ruletext;
    }

    public UniversalRule(DelayRule delayrule, String ruletext) {
        rule = delayrule;
        type = DelayRule.class;
        m_ruletext = ruletext;
    }

    public UniversalRule(AllowedPackageRule allowedpackagerule, String ruletext) {
        rule = allowedpackagerule;
        type = AllowedPackageRule.class;
        m_ruletext = ruletext;
    }

    public UniversalRule(FeatureRule featurerule, String ruletext) {
        rule = featurerule;
        type = FeatureRule.class;
        m_ruletext = ruletext;
    }

    public static UniversalRule getRuleFromText(Context context, String ruletext) {
        Matcher m = Pattern.compile("([^\\s:]+) (.*)").matcher(ruletext);

        if (!m.matches()) {
            throw new AssertionError("no category");
        }

        String category = m.group(1);
        String rest = m.group(2);

        if (category.equals("delay")) {
            int delay;
            try {
                delay = Integer.parseInt(rest);
            } catch (NumberFormatException e) {
                Log.w(TAG, "Delay rule \"" + ruletext + "\" didn't work");
                return null;
            }
            return new UniversalRule(new DelayRule(delay), ruletext);
        } else if (category.equals("allow")) {
            Bundle bundle = RulesManager.parseAllowTextToBundle(context, ruletext);
            if (bundle.containsKey("package") && !bundle.containsKey("host") && !bundle.containsKey("ipv4")) {
                // This is an allowed package
                String packagename = bundle.getString("package");

                return new UniversalRule(new AllowedPackageRule(packagename), ruletext);
            } else if (bundle.containsKey("host") || bundle.containsKey("ipv4")) {
                // This is a whitelisted URL
                RuleAndUid newrule = RulesManager.parseTextToWhitelistRule(context, ruletext);
                if (newrule == null) {
                    throw new AssertionError("Didn't parse into a RuleAndUid");
                }
                return new UniversalRule(newrule, ruletext);
            }
        } else if (category.equals("feature")) {
            return new UniversalRule(new FeatureRule(rest), ruletext);
        }

        return null;
    }
}
