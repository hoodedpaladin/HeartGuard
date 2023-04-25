package eu.faircode.netguard;

import static java.lang.Math.max;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.GuardedBy;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import androidx.preference.PreferenceManager;

import org.apache.commons.codec.binary.Base32;

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

    public static final int MAX_DELAY = 3600*12;

    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    private static volatile RulesManager global_rm = null;

    // Members that contain the current state of rules
    // m_allCurrentRules being the master list, and the rest of these should
    // always be updated based on its contents
    private List<UniversalRule> m_allCurrentRules = new ArrayList<UniversalRule>();
    private boolean m_enabled = true;
    private int m_delay = 0;
    private Map<String, Boolean> m_allowedPackages;
    private boolean m_manage_system = false;

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

        // Set the display fields, at this point, to reflect whether we are showing system apps or not
        updateManageSystem(context);

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

    public static void putNewBoolean(Bundle bundle, String key, boolean value) {
        if (bundle.containsKey(key)) {
            throw new AssertionError("Already contains key " + key);
        }
        bundle.putBoolean(key, value);
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

            m = Pattern.compile("sticky").matcher(phrase);
            if (m.matches()) {
                putNewBoolean(data_bundle, "sticky", true);

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

        int uid;
        String packagename;
        if (data_bundle.containsKey("uid")) {
            uid = data_bundle.getInt("uid");

            if (!data_bundle.containsKey("package")) {
                Log.e(TAG, "expected a package name from rule \"" + text + "\"");
                return null;
            }
            packagename = data_bundle.getString("package");
        } else {
            packagename = null;
            uid = 0;
        }

        boolean sticky = false;
        if (data_bundle.containsKey("sticky")) {
            sticky = data_bundle.getBoolean("sticky");
        }

        if (data_bundle.containsKey("host"))
        {
            if (data_bundle.containsKey("ipv4")) {
                Log.e(TAG, "Rule string " + text + " has invalid combination of types");
                return null;
            }

            return new RuleAndUid(uid, new DomainRule(data_bundle.getString("host"), 1), sticky, packagename);
        }

        if (data_bundle.containsKey("ipv4"))
        {
            if (data_bundle.containsKey("host")) {
                Log.e(TAG, "Rule string " + text + " has invalid combination of types");
                return null;
            }
            return new RuleAndUid(uid, new IPRule(data_bundle.getString("ipv4"), 1), sticky, packagename);
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

    public boolean getPreferenceFilterUdp(Context context) {
        return true;
    }

    // Note: by NetGuard terminology, this boolean value is wifiBlocked, not wifiEnabled
    // False = package is whitelisted!
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

    public boolean getPreferenceManageSystem(Context context) {
        return m_manage_system;
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
        int col_id = cursor.getColumnIndexOrThrow("_id");
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
        int col_id = cursor.getColumnIndexOrThrow("_id");
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
        }

        if (num_enacted > 0) {
            getAllEnactedRulesFromDb(context);
            WhitelistManager.getInstance(context).updateRulesFromRulesManager(context);
            if (!startup) {
                LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent(ActivityMain.ACTION_RULES_CHANGED));
            }
            if (this.getPreferenceEnabled(context)) {
                ServiceSinkhole.reload("rule changed", context, false);
            } else {
                ServiceSinkhole.stop("rule changed", context, false);
            }
        }
    }

    // Sets a row to enacted. Returns true if this makes a runtime change.
    private boolean enactRule(Context context, String ruletext, long id) {
        Log.w(TAG, "Enacting rule \"" + ruletext + "\" ID=" + Long.toString(id));

        if (ruletext.startsWith("- ")) {
            // This is a negative rule
            return enactNegativeRule(context, ruletext, id);
        }
        if (ruletext.matches("abandon .*")) {
            return enactAbandonRule(context, ruletext, id);
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
        if (rule.type == DelayRule.class) {
            Cursor cursor = dh.getEnactedRules();

            int col_ruletext = cursor.getColumnIndexOrThrow("ruletext");
            int col_id = cursor.getColumnIndexOrThrow("_id");

            while (cursor.moveToNext()) {
                Long otherid = cursor.getLong(col_id);

                if (otherid != id) {
                    String otherruletext = cursor.getString(col_ruletext);
                    if (otherruletext.matches("delay \\d+")) {
                        Log.w(TAG, String.format("Removing rule %d because it's also a delay rule", otherid));
                        dh.removeRulesById(new Long[]{otherid});
                    }
                }
            }
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
        int col_id = cursor.getColumnIndexOrThrow("_id");
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

    // Sets a row to enacted. Returns true if this makes a runtime change.
    private boolean enactAbandonRule(Context context, String ruletext, long id) {
        Matcher m = Pattern.compile("abandon (.*)").matcher(ruletext);

        if (!m.matches()) {
            throw new AssertionError("Thought this string was abandon: " + ruletext);
        }

        String otherruletext = m.group(1);

        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        lock.writeLock().lock();
        try {
            Cursor cursor = dh.getRuleMatchingRuletext(otherruletext);

            if (!cursor.moveToFirst()) {
                Log.w(TAG, String.format("Didn't find the positive rule for \"%s\"", ruletext));
                dh.removeRulesById(new Long[]{id});
                return false;
            }
            int col_id = cursor.getColumnIndexOrThrow("_id");
            int col_enacted = cursor.getColumnIndexOrThrow("enacted");

            boolean was_enacted = cursor.getInt(col_enacted) != 0;
            long otherid = cursor.getLong(col_id);

            if (was_enacted) {
                // Can't abandon an enacted rule
                Log.w(TAG, String.format("Not removing ID %d because you can't abandon an enacted rule", otherid));
                dh.removeRulesById(new Long[]{id});
                return false;
            }
            Log.w(TAG, String.format("Removing IDs %d and %d due to abandon rule", id, otherid));
            dh.removeRulesById(new Long[]{id, otherid});

            // Never makes runtime changes, since we can only abandon pending rules
            return false;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void rulesChanged(Context context) {
        Long curr_time = System.currentTimeMillis();

        Log.w(TAG, "Got a rulesChanged update - next pending time was " +
                Long.toString(next_pending_time) + ", time is now " +
                Long.toString(curr_time));

        activateRulesUpTo(context, curr_time, false);

        setAlarmForPending(context);
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

        int major_category;
        int minor_category;

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
            delay = UniversalRule.getRuleFromText(context, ruletext_to_remove).rule.getDelayToRemove(context, m_delay);

            // Category numbers don't matter for this
            major_category = 0;
            minor_category = 0;
        } else if (ruletext.matches("abandon .*")) {
            // Abandon rule
            delay = 0;
            // Category numbers don't matter for this
            major_category = 0;
            minor_category = 0;
        }else {
            // Parse to UniversalRule to get stats on it
            UniversalRule newrule = UniversalRule.getRuleFromText(context, ruletext);

            if (newrule.type == DelayRule.class) {
                if ( ((DelayRule)newrule.rule).getDelay() > MAX_DELAY) {
                    Log.e(TAG, "Max delay is " + MAX_DELAY);
                    String message = context.getString(R.string.maximum_delay, MAX_DELAY);
                    Toast.makeText(context, message, Toast.LENGTH_LONG).show();
                    return;
                }
            }

            // Choose delay based on stats
            delay = newrule.rule.getDelayToAdd(context, m_delay);

            major_category = newrule.getMajorCategory();
            minor_category = newrule.getMinorCategory();
        }

        long curr_time = System.currentTimeMillis();
        long enact_time = curr_time + (delay * 1000L);
        Log.w(TAG, String.format("Queueing new rule \"%s\" with %d delay (enact_time %d)", ruletext, delay, enact_time));
        dh.addNewRule(ruletext, enact_time, 0, major_category, minor_category);

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
        boolean newManageSystem = false;
        Map<String, Boolean> newAllowedPackages = new HashMap<>();


        for (UniversalRule rule : m_allCurrentRules) {
            if (rule.type == DelayRule.class) {
                newDelay = max(newDelay, ((DelayRule)rule.rule).getDelay());
            } else if (rule.type == FeatureRule.class) {
                String featureName = ((FeatureRule)rule.rule).getFeatureName();

                if ("enabled".equals(featureName)) {
                    newEnabled = true;
                }
                if ("manage_system".equals(featureName)) {
                    newManageSystem = true;
                }
            } else if (rule.type == AllowedPackageRule.class) {
                String packageName = ((AllowedPackageRule)rule.rule).getPackageName();

                // False = not filtered i.e. allowed
                newAllowedPackages.put(packageName, false);
            }
        }

        if (m_delay != newDelay) {
            Log.w(TAG, "Delay changed from " + Integer.toString(m_delay) + " to " + Integer.toString(newDelay));
            m_delay = newDelay;
        }
        if (m_enabled != newEnabled) {
            Log.w(TAG, "Enabled changed from " + Boolean.toString(m_enabled) + " to " + Boolean.toString(newEnabled));
            m_enabled = newEnabled;
        }
        if (m_manage_system != newManageSystem) {
            Log.w(TAG, "Manage_system changed from " + Boolean.toString(m_manage_system) + " to " + Boolean.toString(newManageSystem));
            m_manage_system = newManageSystem;

            updateManageSystem(context);
        }
        m_allowedPackages = newAllowedPackages;
    }

    public static String getStringOfRuleDbEntry(Cursor cursor) {
        String message = "DB entry:";
        message += " ID=" + Long.toString(cursor.getLong(cursor.getColumnIndexOrThrow("_id")));
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

    // At the moment of manage_system toggle, or at app startup, the display settings should reflect it
    public void updateManageSystem(Context context) {
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        // Set the internal setting the same
        if (prefs.getBoolean(Rule.PREFERENCE_STRING_MANAGE_SYSTEM, false) != m_manage_system) {
            Log.w(TAG, "Had to update the preference system to set manage_system = " + Boolean.toString(m_manage_system));
            prefs.edit().putBoolean(Rule.PREFERENCE_STRING_MANAGE_SYSTEM, m_manage_system).apply();
        }

        prefs.edit().putBoolean(Rule.PREFERENCE_STRING_SHOW_USER, true).apply();
        prefs.edit().putBoolean(Rule.PREFERENCE_STRING_SHOW_SYSTEM, m_manage_system).apply();
    }

    public void enterExpeditePassword(Context context, String password) {
        lock.writeLock().lock();
        for (UniversalRule rule : m_allCurrentRules) {
            if (rule.type != PartnerRule.class)
                continue;
            PartnerRule partnerRule = (PartnerRule)rule.rule;
            if (partnerRule.tryToUnlock(password)) {
                expediteRules(context);
                return;
            }
        }
    }

    private void expediteRules(Context context) {
        Log.w(TAG, "Expediting rules");
        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        long curr_time = System.currentTimeMillis();
        Cursor cursor = dh.getPendingRules();
        int col_id = cursor.getColumnIndexOrThrow("_id");
        ContentValues cv = new ContentValues();
        cv.put("enact_time", curr_time);

        while (cursor.moveToNext()) {
            long id = cursor.getLong(col_id);
            lock.writeLock().lock();
            try {
                dh.updateRuleWithCV(Long.toString(id), cv);
            } finally {
                lock.writeLock().unlock();
            }
        }

        activateRulesUpTo(context, curr_time, false);
    }

    // Some apps may have lowered delays so that they can be in trial mode
    public int getSpecificDelayForPackage(String m_packagename) {
        // Whitelisted packages have 0 delay
        if (m_allowedPackages.containsKey(m_packagename)) {
            return 0;
        }

        return m_delay;
    }
}

interface RuleWithDelayClassification {
    public int getDelayToAdd(Context context, int main_delay);
    public int getDelayToRemove(Context context, int main_delay);
    public int getMajorCategory();
    public int getMinorCategory();
}

class DelayRule implements RuleWithDelayClassification {
    private int m_delay;

    public DelayRule(int delay) {
        m_delay = delay;
    }

    public int getDelay() {
        return m_delay;
    }

    public int getDelayToAdd(Context context, int main_delay) {
        if (m_delay > main_delay) {
            return 0;
        } else {
            return main_delay - m_delay;
        }
    }

    public int getDelayToRemove(Context context, int main_delay) {
        return main_delay;
    }

    public static UniversalRule parseRule(String ruletext) {
        Matcher m = Pattern.compile("([^\\s:]+) (.*)").matcher(ruletext);

        if (!m.matches()) {
            throw new AssertionError("no category");
        }

        String rest = m.group(2);
        int delay;
        try {
            delay = Integer.parseInt(rest);
        } catch (NumberFormatException e) {
            return null;
        }
        return new UniversalRule(new DelayRule(delay), ruletext);
    }

    public int getMajorCategory() {
        return UniversalRule.MAJOR_CATEGORY_DELAY;
    }

    public int getMinorCategory() {
        return 0;
    }
}

class AllowedPackageRule implements RuleWithDelayClassification {
    private String m_packagename;
    private boolean m_sticky;

    public AllowedPackageRule(String packagename, boolean sticky) {
        m_packagename = packagename;
        m_sticky = sticky;
    }

    public String getPackageName() {
        return m_packagename;
    }

    public int getDelayToAdd(Context context, int main_delay) {
        return main_delay;
    }
    public int getDelayToRemove(Context context, int main_delay) {
        if (m_sticky) {
            return main_delay;
        } else {
            return 0;
        }
    }

    public static UniversalRule parseRule(Context context, String ruletext) {
        Bundle bundle = RulesManager.parseAllowTextToBundle(context, ruletext);

        if (bundle.containsKey("package") && !bundle.containsKey("host") && !bundle.containsKey("ipv4")) {
            // This is an allowed package
            String packagename = bundle.getString("package");
            boolean sticky = false;

            if (bundle.containsKey("sticky")) {
                sticky = bundle.getBoolean("sticky");
            }

            return new UniversalRule(new AllowedPackageRule(packagename, sticky), ruletext);
        } else if (bundle.containsKey("host") || bundle.containsKey("ipv4")) {
            // This is a whitelisted URL
            RuleAndUid newrule = RulesManager.parseTextToWhitelistRule(context, ruletext);
            if (newrule == null)
                return null;
            return new UniversalRule(newrule, ruletext);
        }

        return null;
    }

    public int getMajorCategory() {
        return UniversalRule.MAJOR_CATEGORY_ALLOW;
    }

    public int getMinorCategory() {
        return 0;
    }
}

class FeatureRule implements RuleWithDelayClassification {
    private String m_featurename;
    private enum FeatureType {feature_restrictive, feature_permissive};
    private FeatureType m_featuretype;
    private static final String[] restrictive_features = {"enabled", "manage_system"};

    private static FeatureType getClassificationForName(String featurename) {
        for (String restrictive_feature : restrictive_features) {
            if (restrictive_feature.equals(featurename)) {
                return FeatureType.feature_restrictive;
            }
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

    public int getDelayToAdd(Context context, int main_delay) {
        if (m_featuretype == FeatureType.feature_restrictive) {
            return 0;
        } else if (m_featuretype == FeatureType.feature_permissive) {
            return main_delay;
        } else {
            throw new AssertionError("Problem here");
        }
    }

    public int getDelayToRemove(Context context, int main_delay) {
        if (m_featuretype == FeatureType.feature_restrictive) {
            return main_delay;
        } else if (m_featuretype == FeatureType.feature_permissive) {
            return 0;
        } else {
            throw new AssertionError("Problem here");
        }
    }

    public static UniversalRule parseRule(String ruletext) {
        Matcher m = Pattern.compile("([^\\s:]+) (.*)").matcher(ruletext);

        if (!m.matches()) {
            throw new AssertionError("no category");
        }

        String rest = m.group(2);
        return new UniversalRule(new FeatureRule(rest), ruletext);
    }

    public int getMajorCategory() {
        return UniversalRule.MAJOR_CATEGORY_FEATURE;
    }

    public int getMinorCategory() {
        return 0;
    }
}

// Rule class for partners who can expedite your rules
class PartnerRule implements RuleWithDelayClassification {
    public static int TYPE_TOTP = 1;
    public static int TYPE_PASSWORD = 2;

    private int m_type;
    private String m_key;
    private String m_name;

    public PartnerRule(int type, String key, String name) {
        m_type = type;
        m_key = key;
        m_name = name;
    }

    public int getDelayToAdd(Context context, int main_delay) {
        return main_delay;
    }
    public int getDelayToRemove(Context context, int main_delay) {
        return 0;
    }

    public static UniversalRule parseRule(String ruletext) {
        Matcher m = Pattern.compile("([^\\s:]+) (.*)").matcher(ruletext);

        if (!m.matches()) {
            throw new AssertionError("no category");
        }

        String rest = m.group(2);

        PartnerRule partnerRule = null;

        m = Pattern.compile("name:(\\S+) totp:([a-zA-Z0-9]+)").matcher(rest);
        if (m.matches()) {
            String name = m.group(1);
            String key = m.group(2);
            partnerRule = new PartnerRule(TYPE_TOTP, key, name);
        }
        m = Pattern.compile("name:(\\S+) password:(\\S+)").matcher(rest);
        if (m.matches()) {
            String name = m.group(1);
            String password = m.group(2);
            partnerRule = new PartnerRule(TYPE_PASSWORD, password, name);
        }

        if (partnerRule == null) {
            return null;
        }

        return new UniversalRule(partnerRule, ruletext);
    }

    // Check an incoming passcode to see if it matches (password or TOTP)
    public boolean tryToUnlock(String passcode) {

        if (m_type == TYPE_TOTP) {
            byte[] key = new Base32().decode(m_key);
            int codenum;
            try {
                codenum = Integer.parseInt(passcode);
            } catch (NumberFormatException e) {
                return false;
            }

            long current_time = System.currentTimeMillis() / 1000;

            // Compare with the current time period and 4 previous time periods
            // (2 minutes into the past is OK)
            for (int offset = 0; offset > -5; offset--) {
                int totp = TokenCalculator.TOTP_RFC6238(key,
                                                        TokenCalculator.TOTP_DEFAULT_PERIOD,
                                                        current_time,
                                                        TokenCalculator.TOTP_DEFAULT_DIGITS,
                                                        TokenCalculator.DEFAULT_ALGORITHM,
                                                        offset);
                if (totp == codenum) {
                    return true;
                }
            }
        } else if (m_type == TYPE_PASSWORD) {
            return passcode.equals(m_key);
        }

        return false;
    }

    public int getMajorCategory() {
        return UniversalRule.MAJOR_CATEGORY_PARTNER;
    }

    public int getMinorCategory() {
        return 0;
    }
}

class UniversalRule {
    private static final String TAG = "NetGuard.UniversalRule";

    public static final int MAJOR_CATEGORY_DELAY = 100;
    public static final int MAJOR_CATEGORY_FEATURE = 200;
    public static final int MAJOR_CATEGORY_PARTNER = 300;
    public static final int MAJOR_CATEGORY_ALLOW = 400;

    public RuleWithDelayClassification rule;
    public Class type;
    private String m_ruletext;

    private static final Map<String, Class> classList;
    static {
        classList = new HashMap<>();
        classList.put("delay", DelayRule.class);
        classList.put("allow", AllowedPackageRule.class);
        classList.put("feature", FeatureRule.class);
    }

    public UniversalRule(RuleWithDelayClassification newrule, String ruletext) {
        if (newrule == null)
            throw new AssertionError("Got a null rule for \"" + ruletext + "\"");
        rule = newrule;

        type = null;
        if (rule instanceof RuleAndUid) {
            type = RuleAndUid.class;
        } else if (rule instanceof DelayRule) {
            type = DelayRule.class;
        } else if (rule instanceof AllowedPackageRule) {
            type = AllowedPackageRule.class;
        } else if (rule instanceof FeatureRule) {
            type = FeatureRule.class;
        } else if (rule instanceof PartnerRule) {
            type = PartnerRule.class;
        }

        if (type == null)
            throw new AssertionError("Unknown type for \"" + ruletext + "\"");

        m_ruletext = ruletext;
    }

    public static UniversalRule getRuleFromText(Context context, String ruletext) {
        Matcher m = Pattern.compile("([^\\s:]+) (.*)").matcher(ruletext);

        if (!m.matches()) {
            throw new AssertionError("no category");
        }

        String category = m.group(1);

        UniversalRule therule = null;
        if (category.equals("delay")) {
            therule = DelayRule.parseRule(ruletext);
        } else if (category.equals("allow")) {
            therule = AllowedPackageRule.parseRule(context, ruletext);
        } else if (category.equals("feature")) {
            therule = FeatureRule.parseRule(ruletext);
        } else if (category.equals("partner")) {
            therule = PartnerRule.parseRule(ruletext);
        }

        if (therule == null) {
            Log.e(TAG, "Ruletext \"" + ruletext + "\" didn't get a rule");
        }
        return therule;
    }

    public int getMajorCategory() {
        return rule.getMajorCategory();
    }

    public int getMinorCategory() {
        return rule.getMinorCategory();
    }
}
