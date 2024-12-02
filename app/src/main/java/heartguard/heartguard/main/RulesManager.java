package heartguard.heartguard.main;

import static java.lang.Math.max;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Log;
import android.widget.Toast;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import androidx.preference.PreferenceManager;

import com.instacart.library.truetime.TrueTime;

import org.apache.commons.codec.binary.Base32;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// HeartGuard code - get and process rules from SQL, make decisions
public class RulesManager {
    private static final String TAG = "NetGuard.RulesManager";

    public static final String ACTION_RULES_UPDATE = "eu.faircode.netguard.RULES_UPDATE";

    // Max delay = 1 week
    public static final int MAX_DELAY = 7 * 3600 * 24;

    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    private static volatile RulesManager global_rm = null;

    // Members that contain the current state of rules
    // m_allCurrentRules being the master list, and the rest of these should
    // always be updated based on its contents
    private List<MyRule> m_allCurrentRules = new ArrayList<>();
    private int m_delay = 0;
    private Map<String, Boolean> m_allowedPackages;
    private Map<String, Integer> m_packageDelays;
    private Map<Integer, Boolean> m_allowedUids;
    private Map<String, Boolean> m_ignoredApps;
    private List<IgnoreRule> m_specificIgnoreRules;
    private List<String> m_blockedDomains;
    private List<String> m_dnses;
    private Map<String, FeatureRule> m_featureRules = new HashMap<>();

    private TrueTime m_trueTime;
    private final boolean useTrueTime = false;

    private ExecutorService executor = Executors.newCachedThreadPool();

    HandlerThread backgroundThread;
    Handler handler;

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
        backgroundThread = new HandlerThread("HeartGuard RM bg");
        backgroundThread.start();
        handler = new Handler(backgroundThread.getLooper());
        if (useTrueTime) {
            m_trueTime = TrueTime.build().withSharedPreferencesCache(context).withLoggingEnabled(true);
        } else {
            m_trueTime = null;
        }

        // Now parse all rules
        // (Do this before any other logical steps, just in case we logically need the
        // current rules for our decisions.)
        getAllEnactedRulesFromDb(context);

        // Set the display fields, at this point, to reflect whether we are showing system apps or not
        updateManageSystem(context);

        // Launch a TrueTime request so that, using the true time, we can
        // activate rules that took effect while we were asleep.
        startTrueTimeRequest(context);
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
    public static Bundle parseAllowTextToBundle(String text) {
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
                putNewString(data_bundle, "package", m.group(1));

                // Done parsing this phrase
                continue;
            }

            m = Pattern.compile("host:(.+)").matcher(phrase);
            if (m.matches()) {
                putNewString(data_bundle, "host", m.group(1));

                // Done parsing this phrase
                continue;
            }

            m = Pattern.compile("ip:(.+)").matcher(phrase);
            if (m.matches()) {
                putNewString(data_bundle, "ip", m.group(1));

                // Done parsing this phrase
                continue;
            }

            if (phrase.equals("sticky")) {
                putNewBoolean(data_bundle, "sticky", true);

                // Done parsing this phrase
                continue;
            }

            if (phrase.equals("directip")) {
                putNewBoolean(data_bundle, "directip", true);

                // Done parsing this phrase
                continue;
            }

            m = Pattern.compile("uid:(.+)").matcher(phrase);
            if (m.matches()) {
                putNewString(data_bundle, "uid", m.group(1));

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
    public static RuleAndPackage parseTextToWhitelistRule(Context context, String ruletext) {
        Bundle data_bundle = parseAllowTextToBundle(ruletext);

        if (data_bundle == null)
            return null;

        String packagename;
        if (data_bundle.containsKey("package")) {
            packagename = data_bundle.getString("package");
        } else {
            packagename = null;
        }

        boolean sticky = false;
        if (data_bundle.containsKey("sticky")) {
            sticky = data_bundle.getBoolean("sticky");
        }

        boolean directip = false;
        if (data_bundle.containsKey("directip")) {
            directip = data_bundle.getBoolean("directip");
        }

        RuleForApp apprule = null;

        if (data_bundle.containsKey("host"))
        {
            if (directip) {
                Log.e(TAG, "Rule string " + ruletext + " has invalid combination of types");
                return null;
            }
            if (data_bundle.containsKey("ip")) {
                Log.e(TAG, "Rule string " + ruletext + " has invalid combination of types");
                return null;
            }

            apprule = new DomainRule(ruletext, data_bundle.getString("host"), 1);
        }
        else if (data_bundle.containsKey("ip"))
        {
            if (directip) {
                Log.e(TAG, "Rule string " + ruletext + " has invalid combination of types");
                return null;
            }
            if (data_bundle.containsKey("host")) {
                Log.e(TAG, "Rule string " + ruletext + " has invalid combination of types");
                return null;
            }
            apprule = new IPRule(ruletext, data_bundle.getString("ip"), 1);
        }
        else if (directip) {
            if (data_bundle.containsKey("ip")) {
                Log.e(TAG, "Rule string " + ruletext + " has invalid combination of types");
                return null;
            }
            if (data_bundle.containsKey("host")) {
                Log.e(TAG, "Rule string " + ruletext + " has invalid combination of types");
                return null;
            }

            apprule = new DirectIPRule(ruletext);
        }

        if (apprule == null)
            return null;
        return new RuleAndPackage(ruletext, context, apprule, sticky, packagename);
    }

    // Give a copy of the current whitelist rules
    public List<RuleAndPackage> getCurrentRules(Context context) {
        if (hasFeatureRule(FeatureRule.FEATURE_NAME_LOCKDOWN)) {
            return Collections.EMPTY_LIST;
        }
        lock.readLock().lock();
        List<RuleAndPackage> results = new ArrayList<>();

        for (MyRule rule : m_allCurrentRules) {
            if (rule instanceof RuleAndPackage) {
                results.add((RuleAndPackage)rule);
            }
        }
        lock.readLock().unlock();

        return results;
    }

    public boolean getPreferenceFilter(Context context) {
        return true;
    }

    public boolean getPreferenceEnabled(Context context) {
        return hasFeatureRule(FeatureRule.FEATURE_NAME_ENABLED);
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

    // "feature capture_all_traffic" means that even whitelisted apps will use the VPN.
    // If this is off, whitelisted apps are excluded from the VPN.
    // When capture_all_traffic is enabled, "Block connections without VPN" can be turned on so
    // that traffic can't flow at all except for through HeartGuard.
    // When capture_all_traffic is disabled, "Block connections without VPN" should NOT be turned on,
    // otherwise whitelisted apps will not work.
    public boolean getPreferenceCaptureAllTraffic(Context context) {
        return hasFeatureRule(FeatureRule.FEATURE_NAME_CAPTURE_ALL_TRAFFIC);
    }
    public boolean getPreferenceAllowLogging(Context context) { return hasFeatureRule(FeatureRule.FEATURE_NAME_ALLOW_LOGGING);}

    public boolean getPreferenceNotifyApp(Context context, String packageName)
    {
        if (m_ignoredApps.containsKey(packageName) && m_ignoredApps.get(packageName) == true) {
            return false;
        }
        return true;
    }
    // Note: by NetGuard terminology, this boolean value is wifiBlocked, not wifiEnabled
    // False = package is whitelisted!
    public boolean getWifiEnabledForApp(Context context, String packagename, int uid, boolean defaultVal) {
        if (hasFeatureRule(FeatureRule.FEATURE_NAME_LOCKDOWN)) {
            return true;
        }
        if (m_allowedUids.containsKey(uid)) {
            return m_allowedUids.get(uid);
        }
        if (m_allowedPackages.containsKey(packagename)) {
            return m_allowedPackages.get(packagename);
        }
        return defaultVal;
    }
    public boolean getOtherEnabledForApp(Context context, String packagename, int uid, boolean defaultVal) {
        // Identical settings to above
        return getWifiEnabledForApp(context, packagename, uid, defaultVal);
    }
    public boolean getScreenWifiEnabledForApp(Context context, String packagename, int uid, boolean defaultVal) {
        // Identical settings to above
        return getWifiEnabledForApp(context, packagename, uid, defaultVal);
    }
    public boolean getScreenOtherEnabledForApp(Context context, String packagename, int uid, boolean defaultVal) {
        // Identical settings to above
        return getWifiEnabledForApp(context, packagename, uid, defaultVal);
    }

    public boolean getPreferenceManageSystem(Context context) {
        return getFeatureRule(FeatureRule.FEATURE_NAME_MANAGE_SYSTEM) != null;
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

    private void setAlarmForPending(Context context, long realTime, long systemTime) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        try (Cursor cursor = dh.getPendingRules()) {

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

            Log.w(TAG, "Pending rule \"" + sanitizeRuletext(ruletext) + "\" ID=" + Long.toString(id) + " enact_time=" + Long.toString(enact_time));

            // enact_time is in real time, but the alarm is set in system time
            // So do some math to make it true
            long offset = systemTime - realTime;
            long enact_system_time = enact_time + offset;
            setAlarmForTime(context, enact_system_time);
        }
    }

    // Activate all rules up to a certain time.
    // Upon initial object creation, set startup=true, and we will not reload rules / alert listeners
    private void activateRulesUpTo(Context context, long current_time, boolean startup) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);

        try (Cursor cursor = dh.getPendingRules()) {
            int col_ruletext = cursor.getColumnIndexOrThrow("ruletext");
            int col_id = cursor.getColumnIndexOrThrow("_id");
            int col_enact_time = cursor.getColumnIndexOrThrow("enact_time");

            int num_enacted = 0;
            List<String> enacted_ruletexts = new LinkedList<>();
            while (cursor.moveToNext()) {
                String ruletext = cursor.getString(col_ruletext);
                long id = cursor.getLong(col_id);
                long enact_time = cursor.getLong(col_enact_time);

                Log.d(TAG, "Pending rule \"" + sanitizeRuletext(ruletext) + "\" ID=" + Long.toString(id) + " enact_time=" + Long.toString(enact_time));

                if (enact_time > current_time) {
                    break;
                }
                boolean changed = enactRule(context, ruletext, id);
                if (changed) {
                    num_enacted += 1;
                    enacted_ruletexts.add(ruletext);
                }
            }

            if (num_enacted > 0) {
                // Move all rules from text to RM and WM
                getAllEnactedRulesFromDb(context);
                WhitelistManager.getInstance(context).updateRulesFromRulesManager(context);
                if (!startup) {
                    LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent(ActivityMain.ACTION_RULES_CHANGED));
                }
                // Now, manipulate all access rules to match how they should be
                Set<String> actions = new HashSet<>();
                for (String ruletext : enacted_ruletexts) {
                    Set<String> new_actions = postAddActionsForRuletext(context, ruletext);
                    if (new_actions != null) {
                        actions.addAll(new_actions);
                    }
                }

                boolean reload = false;
                boolean clear_dns = false;
                List<Integer> uids_to_reload = new LinkedList<>();

                for (String action : actions) {
                    if (action == "reload") {
                        reload = true;
                        continue;
                    }

                    if (action == "clear_dns") {
                        clear_dns = true;
                        reload = true;
                        continue;
                    }

                    Matcher m = Pattern.compile("uid (\\d+)").matcher(action);
                    if (m.matches()) {
                        int uid = Integer.parseInt(m.group(1));
                        uids_to_reload.add(uid);
                        continue;
                    }

                    // Unknown string
                    Log.e(TAG, "Unknown action " + action);
                    reload = true;
                    break;
                }

                if (clear_dns) {
                    DatabaseHelper.getInstance(context).clearDns();
                }
                // Just reload the service if we have to reload or if there are a lot of UIDs to reload
                if (reload || (uids_to_reload.size() > 4)) {
                    // Now, reload the ServiceSinkhole
                    if (this.getPreferenceEnabled(context)) {
                        ServiceSinkhole.reload("rule changed", context, false);
                    } else {
                        ServiceSinkhole.stop("rule changed", context, false);
                    }
                } else {
                    // Reload the UIDs individually
                    for (int uid : uids_to_reload) {
                        ServiceSinkhole.pleaseUpdateUid(uid, context);
                    }
                }
            }
        }
    }

    // Called for each ruletext string that succeeds, but after the RM and WM have updated.
    // These actions should generally tend to the access rules
    private Set<String> postAddActionsForRuletext(Context context, String ruletext) {
        if (ruletext.matches("- .*")) {
            String neg_ruletext = ruletext.substring(2);
            MyRule rule = MyRule.getRuleFromText(context, neg_ruletext);
            return rule.getActionsAfterRemove(context);
        } else {
            MyRule rule = MyRule.getRuleFromText(context, ruletext);
            return rule.getActionsAfterAdd(context);
        }
    }

    // Sets a row to enacted. Returns true if this makes a runtime change.
    private boolean enactRule(Context context, String ruletext, long id) {
        Log.w(TAG, "Enacting rule \"" + sanitizeRuletext(ruletext) + "\" ID=" + Long.toString(id));

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

        MyRule rule = MyRule.getRuleFromText(context, ruletext);
        if (rule == null) {
            Log.e(TAG, "Ruletext \"" + ruletext + "\" didn't make a rule");
            return false;
        }

        Map<Long, String> rulesToRemove = rule.getRulesToRemoveAfterAdd(context);
        if (rulesToRemove.size() > 0){
            List<Long> idsToRemove = new ArrayList<>();
            for (Long removalId : rulesToRemove.keySet()) {
                Log.i(TAG, "Remove rule " + removalId + ": \"" + rulesToRemove.get(removalId) + "\"");
                idsToRemove.add(removalId);
            }
            dh.removeRulesById(idsToRemove.toArray(new Long[0]));
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
        try (Cursor cursor = dh.getRuleMatchingRuletext(otherruletext)) {

            if (!cursor.moveToFirst()) {
                Log.w(TAG, String.format("Didn't find the positive rule for \"%s\"", sanitizeRuletext(ruletext)));
                dh.removeRulesById(new Long[]{id});
                return false;
            }
            int col_id = cursor.getColumnIndexOrThrow("_id");
            int col_enacted = cursor.getColumnIndexOrThrow("enacted");

            boolean was_enacted = cursor.getInt(col_enacted) > 0;
            long otherid = cursor.getLong(col_id);

            Log.w(TAG, String.format("Removing IDs %d and %d due to deletion rule", id, otherid));
            dh.removeRulesById(new Long[]{id, otherid});

            return was_enacted;
        }
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
        try (Cursor cursor = dh.getRuleMatchingRuletext(otherruletext)) {
            if (!cursor.moveToFirst()) {
                Log.w(TAG, String.format("Didn't find the positive rule for \"%s\"", sanitizeRuletext(ruletext)));
                dh.removeRulesById(new Long[]{id});
                return false;
            }
            int col_id = cursor.getColumnIndexOrThrow("_id");
            int col_enacted = cursor.getColumnIndexOrThrow("enacted");

            boolean was_enacted = cursor.getInt(col_enacted) > 0;
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

    List<String> m_rulesToCommit = new LinkedList<>();
    public void queueRuleText(Context context, String ruletext) {
        lock.writeLock().lock();

        ruletext = ruletext.replaceAll("\\s+", " ");
        ruletext = ruletext.trim();
        // Add to the commit waiting list
        try {
            m_rulesToCommit.add(ruletext);
        } finally {
            lock.writeLock().unlock();
        }

        // Then request the true time so that we can commit it
        startTrueTimeRequest(context);
    }

    private void commitQueuedRules(Context context, long realTime) {
        List<String> rulesToCommit = new LinkedList<>();

        // Drain entries from the linked list while holding the lock
        lock.writeLock().lock();
        try {
            while (!m_rulesToCommit.isEmpty()) {
                rulesToCommit.add(m_rulesToCommit.remove(0));
            }
        } finally {
            lock.writeLock().unlock();
        }

        // Then queue them
        for (String ruletext : rulesToCommit) {
            commitRuleText(context, ruletext, realTime);
        }
    }

    // Commits a rule to the database, but uses realTime to be sure
    public void commitRuleText(Context context, String ruletext, long realTime) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        int delay = m_delay;

        // Check for existing (enacted or pending) rule
        try (Cursor existing_rule = dh.getRuleMatchingRuletext(ruletext)) {
            if (existing_rule.moveToFirst()) {
                Log.w(TAG, String.format("Rule \"%s\" already exists", sanitizeRuletext(ruletext)));
                return;
            }
        }

        Matcher m = Pattern.compile("- (.*)").matcher(ruletext);

        int major_category;
        int minor_category;

        if (m.matches()) {
            // This is a negative rule
            String ruletext_to_remove = m.group(1);

            // Not only do we not want a duplicate removal rule, we also don't want to
            // queue a removal for a rule that doesn't exist
            try (Cursor existing_rule = dh.getRuleMatchingRuletext(ruletext_to_remove)) {
                if (!existing_rule.moveToFirst()) {
                    Log.w(TAG, String.format("Rule \"%s\" has nothing to delete", ruletext));
                    return;
                }
            }
            MyRule ruleToDelete = MyRule.getRuleFromText(context, ruletext_to_remove);
            if (ruleToDelete == null) {
                Log.e(TAG, "Rule to delete, \"" + ruletext_to_remove + "\" isn't a rule?? Guess we can delete it instantly");
                delay = 0;
            } else {
                delay = ruleToDelete.getDelayToRemove(context, m_delay);
            }

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
            // Parse to a rule to get stats on it
            MyRule newrule = MyRule.getRuleFromText(context, ruletext);

            if (newrule == null) {
                Log.e(TAG, "Tried to queue rule \"" + ruletext + "\" but it isn't a rule");
                return;
            }

            if (newrule instanceof DelayRule) {
                if ( ((DelayRule)newrule).getDelay() > MAX_DELAY) {
                    Log.e(TAG, "Max delay is " + MAX_DELAY);
                    String message = context.getString(R.string.maximum_delay, MAX_DELAY);
                    Toast.makeText(context, message, Toast.LENGTH_LONG).show();
                    return;
                }
            }

            // Choose delay based on stats
            delay = newrule.getDelayToAdd(context, m_delay);

            major_category = newrule.getMajorCategory();
            minor_category = newrule.getMinorCategory();
        }

        long enact_time = realTime + (delay * 1000L);
        Log.w(TAG, String.format("Queueing new rule \"%s\" with %d delay (enact_time %d)", sanitizeRuletext(ruletext), delay, enact_time));
        dh.addNewRule(ruletext, realTime, enact_time, 0, major_category, minor_category);
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

        try (Cursor cursor = dh.getEnactedRules()) {
            int col_ruletext = cursor.getColumnIndexOrThrow("ruletext");

            // Read all rules from DB into list
            List<MyRule> allrules = new ArrayList<>();
            while (cursor.moveToNext()) {
                String ruletext = cursor.getString(col_ruletext);
                MyRule rule = MyRule.getRuleFromText(context, ruletext);
                if (rule == null) {
                    Log.e(TAG, "Rule \"" + ruletext + "\" isn't a rule");
                } else {
                    allrules.add(rule);
                }
            }

            m_allCurrentRules = allrules;
            updateFieldsFromCurrentRules(context);

            Log.w(TAG, "Got " + Integer.toString(m_allCurrentRules.size()) + " rules from DB");
        } finally {
            lock.writeLock().unlock();
        }
    }

    private void updateFieldsFromCurrentRules(Context context) {
        // If there are no delay rules, delay will be 0
        int newDelay = 0;
        Map<String, Boolean> newAllowedPackages = new HashMap<>();
        Map<String, Integer> newPackageDelays = new HashMap<>();
        Map<Integer, Boolean> newAllowedUids = new HashMap<>();
        Map<String, Boolean> newIgnoredApps = new HashMap<>();
        List<IgnoreRule> newSpecificIgnoreRules = new LinkedList<>();
        List<String> newBlockedDomains = new ArrayList<>();
        List<String> newDNSes = new ArrayList<>();
        Map<String, FeatureRule> newFeatureRules = new HashMap<>();

        for (MyRule rule : m_allCurrentRules) {
            if (rule instanceof DelayRule) {
                DelayRule delayRule = (DelayRule)rule;
                String packageName = delayRule.getPackageName();
                int delay = delayRule.getDelay();

                if (packageName == null) {
                    // Global delay rule
                    newDelay = max(newDelay, ((DelayRule)rule).getDelay());
                } else {
                    // Package-specific delay rule
                    if (!newPackageDelays.containsKey(packageName)) {
                        newPackageDelays.put(packageName, delay);
                    } else {
                        newPackageDelays.put(packageName, max(delay, newPackageDelays.get(packageName)));
                    }
                }
            } else if (rule instanceof FeatureRule) {
                FeatureRule featureRule = (FeatureRule)rule;

                String featureName = ((FeatureRule)rule).getFeatureName();
                newFeatureRules.put(featureName, featureRule);
            } else if (rule instanceof AllowedPackageRule) {
                String packageName = ((AllowedPackageRule)rule).getPackageName();

                // False = not filtered i.e. allowed
                newAllowedPackages.put(packageName, false);
            } else if (rule instanceof AllowedUidRule) {
                int uid = ((AllowedUidRule)rule).getUid();

                newAllowedUids.put(uid, false);
            } else if (rule instanceof IgnoreRule) {
                IgnoreRule ignore = (IgnoreRule)rule;
                if ((ignore.getPackageName() != null) && (ignore.getHostName() == null)) {
                    newIgnoredApps.put(ignore.getPackageName(), true);
                } else {
                    newSpecificIgnoreRules.add(ignore);
                }
            } else if (rule instanceof BlockedDomainRule) {
                BlockedDomainRule blockedDomainRule = (BlockedDomainRule)rule;
                newBlockedDomains.add(blockedDomainRule.getDomainName());
            } else if (rule instanceof DNSRule) {
                DNSRule dnsrule = (DNSRule)rule;
                for (String name : dnsrule.getDomains()) {
                    newDNSes.add(name);
                }
            }

        }

        if (m_delay != newDelay) {
            Log.w(TAG, "Delay changed from " + Integer.toString(m_delay) + " to " + Integer.toString(newDelay));
            m_delay = newDelay;
        }

        for (String featureName : FeatureRule.FEATURE_NAMES) {
            boolean currently_enabled = getFeatureRule(featureName) != null;
            boolean newEnabled = newFeatureRules.containsKey(featureName);
            if (currently_enabled != newEnabled) {
                Log.w(TAG, featureName + " changed from " + Boolean.toString(currently_enabled) + " to " + Boolean.toString(newEnabled));
            }
        }

        m_allowedPackages = newAllowedPackages;
        m_packageDelays = newPackageDelays;
        m_allowedUids = newAllowedUids;
        m_ignoredApps = newIgnoredApps;
        m_specificIgnoreRules = newSpecificIgnoreRules;
        m_blockedDomains = newBlockedDomains;
        m_dnses = newDNSes;
        m_featureRules = newFeatureRules;

        // Make sure to turn the logging toggle switch off if you're not allow to reach it
        if (!getPreferenceAllowLogging(context)) {
            final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);
            prefs.edit().putBoolean(Rule.PREFERENCE_STRING_LOG, false).apply();
        }
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
        try (Cursor cursor = dh.getAllRules()) {
            int i = 0;
            while (cursor.moveToNext()) {
                Log.w(TAG, Integer.toString(i) + ": " + sanitizeRuletext(getStringOfRuleDbEntry(cursor)));
                i += 1;
            }
            Log.w(TAG, Integer.toString(i) + " total entries");
        }
    }

    // At the moment of manage_system toggle, or at app startup, the display settings should reflect it
    public void updateManageSystem(Context context) {
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(context);

        // Set the internal setting the same
        if (prefs.getBoolean(Rule.PREFERENCE_STRING_MANAGE_SYSTEM, false) != hasFeatureRule(FeatureRule.FEATURE_NAME_MANAGE_SYSTEM)) {
            Log.w(TAG, "Had to update the preference system to set manage_system = " + Boolean.toString(hasFeatureRule(FeatureRule.FEATURE_NAME_MANAGE_SYSTEM)));
            prefs.edit().putBoolean(Rule.PREFERENCE_STRING_MANAGE_SYSTEM, hasFeatureRule(FeatureRule.FEATURE_NAME_MANAGE_SYSTEM)).apply();
        }

        prefs.edit().putBoolean(Rule.PREFERENCE_STRING_SHOW_USER, true).apply();
        prefs.edit().putBoolean(Rule.PREFERENCE_STRING_SHOW_SYSTEM, hasFeatureRule(FeatureRule.FEATURE_NAME_MANAGE_SYSTEM)).apply();
    }

    boolean m_pleaseExpedite = false;
    public void enterExpeditePassword(Context context, String password) {
        boolean success = false;

        // Try all enacted rules for password success
        lock.readLock().lock();
        try {
            for (MyRule rule : m_allCurrentRules) {
                if (rule instanceof PartnerRule) {
                    PartnerRule partnerRule = (PartnerRule) rule;
                    if (partnerRule.tryToUnlock(password)) {
                        success = true;
                        break;
                    }
                }
            }
        } finally {
            lock.readLock().unlock();
        }

        if (success) {
            // Start an expedited TrueTime request
            lock.writeLock().lock();
            m_pleaseExpedite = true;
            lock.writeLock().unlock();
            startTrueTimeRequest(context);
        }
    }

    private void expediteRules(Context context, long realTime) {
        Log.w(TAG, "Expediting rules");
        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        try (Cursor cursor = dh.getPendingRules()) {
            int col_id = cursor.getColumnIndexOrThrow("_id");
            ContentValues cv = new ContentValues();
            cv.put("enact_time", realTime);

            while (cursor.moveToNext()) {
                long id = cursor.getLong(col_id);
                lock.writeLock().lock();
                try {
                    dh.updateRuleWithCV(Long.toString(id), cv);
                } finally {
                    lock.writeLock().unlock();
                }
            }
        }

        activateRulesUpTo(context, realTime, false);
    }

    // Some apps may have lowered delays so that they can be in trial mode
    public int getSpecificDelayForPackage(String packageName) {
        // Whitelisted packages have 0 delay
        if (m_allowedPackages.containsKey(packageName)) {
            return 0;
        }
        if (m_packageDelays.containsKey(packageName)) {
            int packageDelay = m_packageDelays.get(packageName);
            if (packageDelay < m_delay) {
                return packageDelay;
            }
        }

        return m_delay;
    }

    // The user has clicked to reset an access rule
    public void resetRulesForAccess(Context context, int uid, String daddr) {
        List<String> ruletexts = new LinkedList<>();

        List<String> daddrs = DatabaseHelper.getInstance(context).getListAlternateQNames(daddr);

        // Check all current rules to see if they apply
        lock.readLock().lock();
        try {
            for (MyRule rule : m_allCurrentRules) {
                if (rule instanceof RuleAndPackage) {
                    RuleAndPackage rap = (RuleAndPackage)rule;
                    if (rap.appliesToAccess(uid, daddrs)) {
                        ruletexts.add("- " + rule.getRuleText());
                    }
                }
            }
        } finally {
            lock.readLock().unlock();
        }

        if (ruletexts.size() > 0) {
            ActivityRulesEntry.startActivityToConfirmRules(context, ruletexts);
        }
    }

    // Starts a new TrueTime runnable
    // The TrueTime runnable gets the true time and then performs all actions associated with true time:
    // queue rules, activate rules, set the alarm
    // The runnable will post itself 2 minutes later if it fails
    public void startTrueTimeRequest(final Context context) {
        handler.post(new Runnable() {
            @Override
            public void run() {
                try {
                    long realTime;

                    if (useTrueTime) {
                        if (!TrueTime.isInitialized()) {
                            m_trueTime.initialize();
                        }
                        Date now = m_trueTime.now();
                        realTime = now.getTime();
                    } else {
                        realTime = System.currentTimeMillis();
                    }
                    long systemTime = System.currentTimeMillis();

                    // Check the expedite boolean under lock
                    lock.readLock().lock();
                    boolean expedite = m_pleaseExpedite;
                    lock.readLock().unlock();

                    commitQueuedRules(context, realTime);
                    if (expedite) {
                        expediteRules(context, realTime);
                        lock.writeLock().lock();
                        m_pleaseExpedite = false;
                        lock.writeLock().unlock();
                    }
                    activateRulesUpTo(context, realTime, false);
                    setAlarmForPending(context, realTime, systemTime);

                    // That was successful, now quit
                    return;
                } catch (IOException e) {
                    Log.e(TAG, "TrueTime request got IOException " + e);
                } catch (Throwable t) {
                    Log.e(TAG, "TrueTime request got throwable " + t);
                }

                handler.postDelayed(this, 120000);
            }
        });
    }

    // Clean up the ruletext to be displayed
    public static String sanitizeRuletext(String ruletext) {
        // Don't show the user the secret information contained in expedite partners!
        ruletext = ruletext.replaceAll("totp:\\S+", "totp:******");
        ruletext = ruletext.replaceAll("password:\\S+", "password:******");
        return ruletext;
    }

    boolean shouldNotifyOnPacket(Context context, Packet packet, String dname) {
        if (dname == null)
            return true;

        String packageName = context.getPackageManager().getNameForUid(packet.uid);
        List<String> alldnames = DatabaseHelper.getInstance(context).getListAlternateQNames(dname);

        for (IgnoreRule ignore : m_specificIgnoreRules) {
            if ((ignore.getPackageName() != null) && (!ignore.getPackageName().equals(packageName))) {
                continue;
            }
            if (ignore.getHostName() != null) {
                boolean matched = false;

                for (String dname2 : alldnames) {
                    if (Util.isAddressInsideDomain(dname2, ignore.getHostName())) {
                        matched = true;
                        break;
                    }
                }
                if (!matched) {
                    continue;
                }
            }
            return false;
        }
        return true;
    }

    public List<String> getBlockedDomains()
    {
        return m_blockedDomains;
    }

    public List<String> getDNSs()
    {
        return m_dnses;
    }

    public FeatureRule getFeatureRule(String featureName) {
        if (!m_featureRules.containsKey(featureName))
            return null;
        return m_featureRules.get(featureName);
    }

    public boolean hasFeatureRule(String featureName) {
        return m_featureRules.containsKey(featureName);
    }
}

class MyRule {
    private static final String TAG = "NetGuard.Rule";
    public static final int MAJOR_CATEGORY_DELAY = 100;
    public static final int MAJOR_CATEGORY_FEATURE = 200;
    public static final int MAJOR_CATEGORY_DNS = 250;
    public static final int MAJOR_CATEGORY_PARTNER = 300;
    public static final int MAJOR_CATEGORY_ALLOW = 400;
    public static final int MAJOR_CATEGORY_BLOCK = 450;
    public static final int MAJOR_CATEGORY_IGNORE = 500;
    public static final int MAJOR_CATEGORY_COMMENT = 600;

    private String m_ruletext;
    private int m_major_category;
    private int m_minor_category;

    public MyRule(String ruletext,
                  int major_category,
                  int minor_category) {
        m_ruletext = ruletext;
        m_major_category = major_category;
        m_minor_category = minor_category;
    }
    public MyRule(String ruletext,
                  int major_category) {
        this(ruletext, major_category, 0);
    }
    public int getDelayToAdd(Context context, int main_delay) {
        return main_delay;
    }
    public int getDelayToRemove(Context context, int main_delay) {
        return main_delay;
    }
    public int getMajorCategory() {
        return m_major_category;
    }
    public int getMinorCategory() {
        return m_minor_category;
    }
    protected void setMinorCategory(int minor_category) {
        m_minor_category = minor_category;
    }
    public String getRuleText() {
        return m_ruletext;
    }

    public Set<String> getActionsAfterAdd(Context context) {
        return null;
    }
    public Set<String> getActionsAfterRemove(Context context) {
        return null;
    }

    public Map<Long, String> getRulesToRemoveAfterAdd(Context context) {
        return new HashMap<Long,String>();
    }
    public static MyRule getRuleFromText(Context context, String ruletext) {
        if (ruletext.startsWith("#")) {
            // Comments can start even without a space ... yeah sure why not
            return new CommentRule(ruletext);
        }
        Matcher m = Pattern.compile("([^\\s:]+) (.*)").matcher(ruletext);

        if (!m.matches()) {
            return null;
        }

        String category = m.group(1);

        MyRule therule = null;
        try {
            if (category.equals("delay")) {
                therule = new DelayRule(ruletext);
            } else if (category.equals("allow")) {
                therule = AllowedPackageRule.parseRule(context, ruletext);
            } else if (category.equals("feature")) {
                therule = FeatureRule.parseRule(ruletext);
            } else if (category.equals("partner")) {
                therule = PartnerRule.parseRule(ruletext);
            } else if (category.equals("ignore")) {
                therule = IgnoreRule.parseRule(ruletext);
            } else if (category.equals("blockdomain")) {
                therule = BlockedDomainRule.parseRule(ruletext);
            } else if (category.equals("dns")) {
                therule = DNSRule.parseRule(ruletext);
            }
        } catch (RuleParseNoMatchException e) {
            therule = null;
        } catch (AssertionError e) {
            Log.e(TAG, "Ruletext \"" + ruletext + "\" got an assertion " + e);
            therule = null;
        } catch (Throwable e) {
            Log.e(TAG, "Ruletext \"" + ruletext + "\" got an exception " + e);
            therule = null;
        }

        if (therule == null) {
            Log.e(TAG, "Ruletext \"" + ruletext + "\" didn't get a rule");
        }
        return therule;
    }
}

class DelayRule extends MyRule {
    private final int m_delay;
    private final String m_packageName;
    private static final int MINOR_CATEGORY_GLOBAL_DELAY = 100;
    private static final int MINOR_CATEGORY_PACKAGE_DELAY = 200;

    public DelayRule(String ruletext) {
        super(ruletext, MAJOR_CATEGORY_DELAY);

        Matcher m = Pattern.compile("delay (\\d+)").matcher(ruletext);
        if (m.matches()) {
            String rest = m.group(1);

            m_delay = Integer.parseInt(rest);
            m_packageName = null;
            super.setMinorCategory(MINOR_CATEGORY_GLOBAL_DELAY);
            return;
        }

        // Ruletext match for a package delay rule
        m = Pattern.compile("delay package:(\\S+) (\\d+)").matcher(ruletext);
        if (m.matches()) {
            m_packageName = m.group(1);
            m_delay = Integer.parseInt(m.group(2));
            super.setMinorCategory(MINOR_CATEGORY_PACKAGE_DELAY);
            return;
        }

        throw new RuleParseNoMatchException();

    }

    public int getDelay() {
        return m_delay;
    }

    // Lengthening a delay is instant, and shortening a delay takes time based on the difference
    // Make sure you are comparing against either the global delay or the specific package delay
    public int getDelayToAdd(Context context, int main_delay) {
        int current_delay;

        if (m_packageName == null) {
            current_delay = main_delay;
        } else {
            current_delay = RulesManager.getInstance(context).getSpecificDelayForPackage(m_packageName);
        }
        if (m_delay > current_delay) {
            return 0;
        } else {
            return current_delay - m_delay;
        }
    }

    public int getDelayToRemove(Context context, int main_delay) {
        if (m_packageName == null) {
            // Removing the main delay = turning to delay 0
            return main_delay;
        } else {
            // Removing a package delay = reverting to normal delay, so this is free
            return 0;
        }
    }

    @Override
    public Map<Long, String> getRulesToRemoveAfterAdd(Context context) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        Map<Long, String> enacted_rules = dh.getEnactedRulesMap();
        Map<Long, String> removals = new HashMap<>();

        for (Long id : enacted_rules.keySet())
        {
            String ruletext = enacted_rules.get(id);
            if (ruletext.equals(this.getRuleText()))
                continue;
            if (ruletext.matches("delay .+"))
            {
                DelayRule otherRule = new DelayRule(ruletext);
                if (otherRule.sameAs(this)) {
                    removals.put(id, ruletext);
                }
            }
        }
        return removals;
    }

    protected String getPackageName() {
        return m_packageName;
    }

    public boolean sameAs(DelayRule otherRule) {
        String otherPackage = otherRule.getPackageName();
        if (m_packageName == null) {
            return (otherPackage == null) || (otherPackage.length() == 0);
        } else {
            return m_packageName.equals(otherPackage);
        }
    }
}

class AllowedPackageRule extends MyRule {
    private static final String TAG = "Netguard.APRule";
    private final String m_packagename;
    private final boolean m_sticky;

    public AllowedPackageRule(String ruletext) {
        super(ruletext, MAJOR_CATEGORY_ALLOW, 0);

        Bundle bundle = RulesManager.parseAllowTextToBundle(ruletext);

        if (bundle.containsKey("package") && !bundle.containsKey("host") && !bundle.containsKey("ip") && !bundle.containsKey("directip")) {
            // This is an allowed package
            m_packagename = bundle.getString("package");
            m_sticky = bundle.getBoolean("sticky", false);
            return;
        }
        // other types aren't handles here
        throw new RuleParseNoMatchException();
    }

    protected String getPackageName() {
        return m_packagename;
    }

    public int getDelayToAdd(Context context, int main_delay) {
        // The RulesManager may have a shortened delay for this package
        RulesManager rm = RulesManager.getInstance(context);
        int specific_delay = rm.getSpecificDelayForPackage(m_packagename);
        if (specific_delay < main_delay) {
            return specific_delay;
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

    public static MyRule parseRule(Context context, String ruletext) {
        Bundle bundle = RulesManager.parseAllowTextToBundle(ruletext);

        if (bundle.containsKey("package") && !bundle.containsKey("host") && !bundle.containsKey("ip") && !bundle.containsKey("directip")) {
            return new AllowedPackageRule(ruletext);
        } else if (bundle.containsKey("uid") && !bundle.containsKey("host") && !bundle.containsKey("ip")) {
            int uid;
            try {
                uid = Integer.parseInt(bundle.getString("uid"));
            } catch (NumberFormatException e) {
                return null;
            }

            boolean sticky = false;

            if (bundle.containsKey("sticky")) {
                sticky = bundle.getBoolean("sticky");
            }
            return new AllowedUidRule(ruletext, uid, sticky);
        } else if (bundle.containsKey("host") || bundle.containsKey("ip") || bundle.containsKey("directip")) {
            // This is a whitelisted URL
            return RulesManager.parseTextToWhitelistRule(context, ruletext);
        }
        throw new RuleParseNoMatchException();
    }

    public Set<String> getActionsAfterAdd(Context context) {
        return Collections.singleton("reload");
    }
    public Set<String> getActionsAfterRemove(Context context) {
        return Collections.singleton("reload");
    }
}

class AllowedUidRule extends MyRule {
    private int m_uid;
    private boolean m_sticky;

    public AllowedUidRule(String ruletext, int uid, boolean sticky) {
        super(ruletext, MAJOR_CATEGORY_ALLOW);
        m_uid = uid;
        m_sticky = sticky;
    }

    public int getUid() {
        return m_uid;
    }

    @Override
    public int getDelayToRemove(Context context, int main_delay) {
        if (m_sticky) {
            return main_delay;
        } else {
            return 0;
        }
    }

    public Set<String> getActionsAfterAdd(Context context) {
        return Collections.singleton("reload");
    }
    public Set<String> getActionsAfterRemove(Context context) {
        return Collections.singleton("reload");
    }
}

class FeatureRule extends MyRule {
    public static final String FEATURE_NAME_ENABLED = "enabled";
    public static final String FEATURE_NAME_MANAGE_SYSTEM = "manage_system";
    public static final String FEATURE_NAME_LOCKDOWN = "lockdown";
    public static final String FEATURE_NAME_CAPTURE_ALL_TRAFFIC = "capture_all_traffic";
    public static final String FEATURE_NAME_ALLOW_LOGGING = "allow_logging";
    public static final String[] FEATURE_NAMES = {
            FEATURE_NAME_ENABLED,
            FEATURE_NAME_MANAGE_SYSTEM,
            FEATURE_NAME_LOCKDOWN,
            FEATURE_NAME_CAPTURE_ALL_TRAFFIC,
            FEATURE_NAME_ALLOW_LOGGING,
    };
    private String m_featurename;
    private enum FeatureType {feature_restrictive, feature_permissive, feature_both};
    private FeatureType m_featuretype;
    private static final String[] restrictive_features = {FEATURE_NAME_ENABLED,
                                                          FEATURE_NAME_MANAGE_SYSTEM,
                                                          FEATURE_NAME_LOCKDOWN,
                                                          FEATURE_NAME_CAPTURE_ALL_TRAFFIC};
    private static final String[] permissive_features = {FEATURE_NAME_ALLOW_LOGGING};
    private static final String[] both_features = {};

    private static FeatureType getClassificationForName(String featurename) {
        for (String restrictive_feature : restrictive_features) {
            if (restrictive_feature.equals(featurename)) {
                return FeatureType.feature_restrictive;
            }
        }

        for (String permissive_feature : permissive_features) {
            if (permissive_feature.equals(featurename)) {
                return FeatureType.feature_permissive;
            }
        }

        for (String permissive_feature : both_features) {
            if (permissive_feature.equals(featurename)) {
                return FeatureType.feature_both;
            }
        }

        throw new AssertionError("feature name \"" + featurename + "\" not present");
    }

    public FeatureRule(String ruletext, String featurename) {
        super(ruletext, MAJOR_CATEGORY_FEATURE);
        m_featurename = featurename;
        m_featuretype = getClassificationForName(featurename);
    }

    public String getFeatureName() {
        return m_featurename;
    }

    public int getDelayToAdd(Context context, int main_delay) {
        if (m_featuretype == FeatureType.feature_restrictive) {
            return 0;
        } else if ((m_featuretype == FeatureType.feature_permissive) || (m_featuretype == FeatureType.feature_both)) {
            return main_delay;
        } else {
            throw new AssertionError("Problem here");
        }
    }

    public int getDelayToRemove(Context context, int main_delay) {
        if ((m_featuretype == FeatureType.feature_restrictive) || (m_featuretype == FeatureType.feature_both)) {
            return main_delay;
        } else if (m_featuretype == FeatureType.feature_permissive) {
            return 0;
        } else {
            throw new AssertionError("Problem here");
        }
    }

    public static FeatureRule parseRule(String ruletext) {
        Matcher m = Pattern.compile("([^\\s:]+) (.*)").matcher(ruletext);

        if (m.matches()) {
            String[] fields = m.group(2).split(" ");

            if (fields[0].equals(FEATURE_NAME_LOCKDOWN)) {
                return LockdownRule.parseRule(ruletext);
            }
            if (fields.length == 1) {
                return new FeatureRule(ruletext, fields[0]);
            }
        }

        throw new RuleParseNoMatchException();
    }

    public Set<String> getActionsAfterAdd(Context context) {
        return Collections.singleton("reload");
    }
    public Set<String> getActionsAfterRemove(Context context) {
        return Collections.singleton("reload");
    }

    @Override
    public Map<Long, String> getRulesToRemoveAfterAdd(Context context) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        Map<Long, String> enacted_rules = dh.getEnactedRulesMap();
        Map<Long, String> removals = new HashMap<>();

        for (Long id : enacted_rules.keySet())
        {
            String ruletext = enacted_rules.get(id);
            if (ruletext.equals(this.getRuleText()))
                continue;
            if (ruletext.matches("feature .+"))
            {
                FeatureRule otherRule = FeatureRule.parseRule(ruletext);
                if (otherRule.getFeatureName().equals(getFeatureName())) {
                    removals.put(id, ruletext);
                }
            }
        }
        return removals;
    }
}

class LockdownRule extends FeatureRule {
    private int m_delay;
    public LockdownRule(String ruletext, String featurename, int delay) throws RuleParseNoMatchException {
        super(ruletext, featurename);
        m_delay = delay;
        if (delay < 0) {
            throw new RuleParseNoMatchException();
        }
    }

    public static LockdownRule parseRule(String ruletext) {
        Matcher m = Pattern.compile("([^\\s:]+) (.*)").matcher(ruletext);

        if (m.matches()) {
            String[] fields = m.group(2).split(" ");

            if (!fields[0].equals(FEATURE_NAME_LOCKDOWN)) {
                throw new RuleParseNoMatchException();
            }
            if (fields.length == 1) {
                return new LockdownRule(ruletext, fields[0], 0);
            }
            if (fields.length == 2) {
                try {
                    int delay = Integer.parseInt(fields[1]);
                    return new LockdownRule(ruletext, fields[0], delay);
                } catch (NumberFormatException e) {
                    throw new RuleParseNoMatchException();
                }
            }
        }

        throw new RuleParseNoMatchException();
    }

    private int getSpecificDelay(int main_delay) {
        if (m_delay == 0) {
            return main_delay;
        }
        return m_delay;
    }

    @Override
    public int getDelayToAdd(Context context, int main_delay) {
        RulesManager rm = RulesManager.getInstance(context);
        FeatureRule otherLockdown = rm.getFeatureRule(FEATURE_NAME_LOCKDOWN);
        if (otherLockdown == null)
            return 0;
        int other_delay = otherLockdown.getDelayToRemove(context, main_delay);
        if (getSpecificDelay(main_delay) >= other_delay)
            return 0;
        return other_delay - getSpecificDelay(main_delay);
    }

    @Override
    public int getDelayToRemove(Context context, int main_delay) {
        if (getSpecificDelay(main_delay) < main_delay) {
            return getSpecificDelay(main_delay);
        }
        return main_delay;
    }
}

// Rule class for partners who can expedite your rules
class PartnerRule extends MyRule {
    public static int TYPE_TOTP = 1;
    public static int TYPE_PASSWORD = 2;

    private int m_type;
    private String m_key;
    private String m_name;

    public PartnerRule(String ruletext, int type, String key, String name) {
        super(ruletext, MAJOR_CATEGORY_PARTNER);
        m_type = type;
        m_key = key;
        m_name = name;
    }

    public int getDelayToRemove(Context context, int main_delay) {
        return 0;
    }

    public static MyRule parseRule(String ruletext) {
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
            return new PartnerRule(ruletext, TYPE_TOTP, key, name);
        }
        m = Pattern.compile("name:(\\S+) password:(\\S+)").matcher(rest);
        if (m.matches()) {
            String name = m.group(1);
            String password = m.group(2);
            return new PartnerRule(ruletext, TYPE_PASSWORD, password, name);
        }

        throw new RuleParseNoMatchException();
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
}

class IgnoreRule extends MyRule {
    private static final String TAG = "NetGuard.IgnoreRule";
    private String m_packageName;
    private String m_hostName;

    public IgnoreRule(String ruletext, String packageName, String hostName) {
        super(ruletext, MAJOR_CATEGORY_IGNORE);
        m_packageName = packageName;
        m_hostName = hostName;
    }

    public int getDelayToAdd(Context context, int main_delay) {
        return 0;
    }
    public int getDelayToRemove(Context context, int main_delay) {
        return 0;
    }

    public static MyRule parseRule(String ruletext) {
        Pattern p = Pattern.compile("ignore (.*)");
        Matcher m = p.matcher(ruletext);
        if (!m.matches())
            return null;
        String constraints = m.group(1);

        String[] separated = constraints.split(" ");

        String packageName = null;
        String hostName = null;
        for (String phrase : separated) {
            m = Pattern.compile("package:(.*)").matcher(phrase);
            if (m.matches()) {
                packageName = m.group(1);
                continue;
            }

            m = Pattern.compile("host:(.+)").matcher(phrase);
            if (m.matches()) {
                hostName = m.group(1);
                continue;
            }

            Log.e(TAG, "\"" + ruletext + "\" didn't contain any recognized phrases");
            return null;
        }

        if (!((packageName != null) || (hostName != null))) {
            return null;
        }
        return new IgnoreRule(ruletext, packageName, hostName);
    }

    public String getPackageName() {
        return m_packageName;
    }

    public String getHostName() {
        return m_hostName;
    }
}

class BlockedDomainRule extends MyRule {
    private String m_domainName;
    private boolean m_try;

    BlockedDomainRule(String ruletext, String domainName, boolean bTry) {
        super(ruletext, MAJOR_CATEGORY_BLOCK);
        this.m_domainName = domainName;
        this.m_try = bTry;
    }

    public int getDelayToAdd(Context context, int main_delay) {
        return 0;
    }
    public int getDelayToRemove(Context context, int main_delay) {
        if (m_try)
            return 0;
        return main_delay;
    }

    public String getDomainName() {
        return m_domainName;
    }

    public static MyRule parseRule(String ruletext)
    {
        Pattern p = Pattern.compile("blockdomain (.+)");
        Matcher m = p.matcher(ruletext);
        if (!m.matches())
            return null;
        String[] params = m.group(1).trim().split("\\s+");
        String domainName = null;
        boolean bTry = false;

        for (String param : params)
        {
            if (param.equals("try"))
            {
                bTry = true;
            }
            else
            {
                if (domainName != null)
                {
                    return null;
                }
                else
                {
                    domainName = param;
                }
            }
        }

        if ((domainName == null ) || (domainName == ""))
        {
            return null;
        }
        return new BlockedDomainRule(ruletext, domainName, bTry);
    }

    public Set<String> getActionsAfterAdd(Context context) {

        Set<String> results = new HashSet<>();
        results.add("reload");
        results.add("clear_dns");
        return results;
    }
    public Set<String> getActionsAfterRemove(Context context) {
        return getActionsAfterAdd(context);
    }
}

class DNSRule extends MyRule {
    private List<String> m_dnses;

    DNSRule(String ruletext, String dns1, String dns2) {
        super(ruletext, MAJOR_CATEGORY_DNS);
        m_dnses = new ArrayList<>();
        m_dnses.add(dns1);
        m_dnses.add(dns2);
    }
    public static MyRule parseRule(String ruletext)
    {
        Pattern p = Pattern.compile("dns (\\S+) (\\S+)");
        Matcher m = p.matcher(ruletext);
        if (!m.matches())
            return null;
        return new DNSRule(ruletext, m.group(1), m.group(2));
    }

    public Set<String> getActionsAfterAdd(Context context) {

        Set<String> results = new HashSet<>();
        results.add("reload");
        results.add("clear_dns");
        return results;
    }
    public Set<String> getActionsAfterRemove(Context context) {
        return getActionsAfterAdd(context);
    }

    public List<String> getDomains() {
        return m_dnses;
    }

    @Override
    public Map<Long, String> getRulesToRemoveAfterAdd(Context context) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        Map<Long, String> enacted_rules = dh.getEnactedRulesMap();
        Map<Long, String> removals = new HashMap<>();

        for (Long id : enacted_rules.keySet())
        {
            String ruletext = enacted_rules.get(id);
            if (ruletext.equals(this.getRuleText()))
                continue;
            if (ruletext.matches("dns .+"))
            {
                removals.put(id, ruletext);
            }
        }
        return removals;
    }

}

class CommentRule extends MyRule {
    CommentRule(String ruletext) {
        super(ruletext, MAJOR_CATEGORY_COMMENT);
    }

    public int getDelayToAdd(Context context, int main_delay) {
        return 0;
    }
    public int getDelayToRemove(Context context, int main_delay) {
        return 0;
    }
}

class RuleParseNoMatchException extends AssertionError{};