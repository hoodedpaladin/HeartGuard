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
    private List<UniversalRule> m_allCurrentRules = new ArrayList<UniversalRule>();
    private boolean m_enabled = true;
    private boolean m_capture_all_traffic = false;
    private int m_delay = 0;
    private Map<String, Boolean> m_allowedPackages;
    private boolean m_manage_system = false;
    private boolean m_allow_logging = false;
    private Map<String, Integer> m_packageDelays;
    private Map<Integer, Boolean> m_allowedUids;
    private Map<String, Boolean> m_ignoredApps;
    private List<IgnoreRule> m_specificIgnoreRules;
    private List<String> m_blockedDomains;

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
    public static RuleAndPackage parseTextToWhitelistRule(Context context, String text) {
        Bundle data_bundle = parseAllowTextToBundle(context, text);

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

        if (data_bundle.containsKey("host"))
        {
            if (directip) {
                Log.e(TAG, "Rule string " + text + " has invalid combination of types");
                return null;
            }
            if (data_bundle.containsKey("ip")) {
                Log.e(TAG, "Rule string " + text + " has invalid combination of types");
                return null;
            }

            return new RuleAndPackage(context, new DomainRule(text, data_bundle.getString("host"), 1), sticky, packagename);
        }

        if (data_bundle.containsKey("ip"))
        {
            if (directip) {
                Log.e(TAG, "Rule string " + text + " has invalid combination of types");
                return null;
            }
            if (data_bundle.containsKey("host")) {
                Log.e(TAG, "Rule string " + text + " has invalid combination of types");
                return null;
            }
            return new RuleAndPackage(context, new IPRule(text, data_bundle.getString("ip"), 1), sticky, packagename);
        }

        if (directip) {
            if (data_bundle.containsKey("ip")) {
                Log.e(TAG, "Rule string " + text + " has invalid combination of types");
                return null;
            }
            if (data_bundle.containsKey("host")) {
                Log.e(TAG, "Rule string " + text + " has invalid combination of types");
                return null;
            }

            return new RuleAndPackage(context, new DirectIPRule(text), sticky, packagename);
        }

        // No rule found
        return null;
    }

    // Give a copy of the current whitelist rules
    public List<RuleAndPackage> getCurrentRules(Context context) {
        lock.readLock().lock();
        List<RuleAndPackage> results = new ArrayList<>();

        for (UniversalRule rule : m_allCurrentRules) {
            if (rule.type == RuleAndPackage.class) {
                results.add((RuleAndPackage)rule.rule);
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

    // "feature capture_all_traffic" means that even whitelisted apps will use the VPN.
    // If this is off, whitelisted apps are excluded from the VPN.
    // When capture_all_traffic is enabled, "Block connections without VPN" can be turned on so
    // that traffic can't flow at all except for through HeartGuard.
    // When capture_all_traffic is disabled, "Block connections without VPN" should NOT be turned on,
    // otherwise whitelisted apps will not work.
    public boolean getPreferenceCaptureAllTraffic(Context context) {
        return m_capture_all_traffic;
    }
    public boolean getPreferenceAllowLogging(Context context) { return m_allow_logging;}

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
            UniversalRule rule = UniversalRule.getRuleFromText(context, neg_ruletext);
            return rule.rule.getActionsAfterRemove(context);
        } else {
            UniversalRule rule = UniversalRule.getRuleFromText(context, ruletext);
            return rule.rule.getActionsAfterAdd(context);
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

        UniversalRule rule = UniversalRule.getRuleFromText(context, ruletext);
        if (rule == null) {
            Log.e(TAG, "Ruletext \"" + ruletext + "\" didn't make a rule");
            return false;
        }

        if (rule.type == DelayRule.class) {
            try (Cursor cursor = dh.getEnactedRules()) {
                DelayRule delayRule = (DelayRule) rule.rule;

                int col_ruletext = cursor.getColumnIndexOrThrow("ruletext");
                int col_id = cursor.getColumnIndexOrThrow("_id");

                while (cursor.moveToNext()) {
                    Long otherid = cursor.getLong(col_id);

                    if (otherid != id) {
                        String otherruletext = cursor.getString(col_ruletext);
                        if (otherruletext.matches("delay .+")) {
                            DelayRule otherRule = (DelayRule) (DelayRule.parseRule(otherruletext).rule);
                            if (delayRule.sameAs(otherRule)) {
                                Log.w(TAG, String.format("Removing rule %d because it's also a delay rule", otherid));
                                dh.removeRulesById(new Long[]{otherid});
                            }
                        }
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
            UniversalRule ruleToDelete = UniversalRule.getRuleFromText(context, ruletext_to_remove);
            if (ruleToDelete == null) {
                Log.e(TAG, "Rule to delete, \"" + ruletext_to_remove + "\" isn't a rule?? Guess we can delete it instantly");
                delay = 0;
            } else {
                delay = ruleToDelete.rule.getDelayToRemove(context, m_delay);
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
            // Parse to UniversalRule to get stats on it
            UniversalRule newrule = UniversalRule.getRuleFromText(context, ruletext);

            if (newrule == null) {
                Log.e(TAG, "Tried to queue rule \"" + ruletext + "\" but it isn't a rule");
                return;
            }

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
            List<UniversalRule> allrules = new ArrayList<UniversalRule>();
            while (cursor.moveToNext()) {
                String ruletext = cursor.getString(col_ruletext);
                UniversalRule rule = UniversalRule.getRuleFromText(context, ruletext);
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
        boolean newEnabled = false;
        boolean newManageSystem = false;
        boolean newCaptureAllTraffic = false;
        boolean newAllowLogging = false;
        Map<String, Boolean> newAllowedPackages = new HashMap<>();
        Map<String, Integer> newPackageDelays = new HashMap<>();
        Map<Integer, Boolean> newAllowedUids = new HashMap<>();
        Map<String, Boolean> newIgnoredApps = new HashMap<>();
        List<IgnoreRule> newSpecificIgnoreRules = new LinkedList<>();
        List<String> newBlockedDomains = new ArrayList<>();

        for (UniversalRule rule : m_allCurrentRules) {
            if (rule.type == DelayRule.class) {
                DelayRule delayRule = (DelayRule)rule.rule;
                String packageName = delayRule.getPackageName();
                int delay = delayRule.getDelay();

                if (packageName == null) {
                    // Global delay rule
                    newDelay = max(newDelay, ((DelayRule)rule.rule).getDelay());
                } else {
                    // Package-specific delay rule
                    if (!newPackageDelays.containsKey(packageName)) {
                        newPackageDelays.put(packageName, delay);
                    } else {
                        newPackageDelays.put(packageName, max(delay, newPackageDelays.get(packageName)));
                    }
                }
            } else if (rule.type == FeatureRule.class) {
                String featureName = ((FeatureRule)rule.rule).getFeatureName();

                if ("enabled".equals(featureName)) {
                    newEnabled = true;
                }
                if ("manage_system".equals(featureName)) {
                    newManageSystem = true;
                }
                if ("capture_all_traffic".equals(featureName)) {
                    newCaptureAllTraffic = true;
                }
                if ("allow_logging".equals(featureName)) {
                    newAllowLogging = true;
                }
            } else if (rule.type == AllowedPackageRule.class) {
                String packageName = ((AllowedPackageRule)rule.rule).getPackageName();

                // False = not filtered i.e. allowed
                newAllowedPackages.put(packageName, false);
            } else if (rule.type == AllowedUidRule.class) {
                int uid = ((AllowedUidRule)rule.rule).getUid();

                newAllowedUids.put(uid, false);
            } else if (rule.type == IgnoreRule.class) {
                IgnoreRule ignore = (IgnoreRule)rule.rule;
                if ((ignore.getPackageName() != null) && (ignore.getHostName() == null)) {
                    newIgnoredApps.put(ignore.getPackageName(), true);
                } else {
                    newSpecificIgnoreRules.add(ignore);
                }
            } else if (rule.type == BlockedDomainRule.class) {
                BlockedDomainRule blockedDomainRule = (BlockedDomainRule)rule.rule;
                newBlockedDomains.add(blockedDomainRule.getDomainName());
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
        if (m_capture_all_traffic != newCaptureAllTraffic) {
            Log.w(TAG, "Capture_all_traffic changed from " + Boolean.toString(m_capture_all_traffic) + " to " + Boolean.toString(newCaptureAllTraffic));
            m_capture_all_traffic = newCaptureAllTraffic;
        }
        if (m_allow_logging != newAllowLogging) {
            Log.w(TAG, "Allow Logging changed from " + Boolean.toString(m_allow_logging) + " to " + Boolean.toString(newAllowLogging));
            m_allow_logging = newAllowLogging;
        }
        m_allowedPackages = newAllowedPackages;
        m_packageDelays = newPackageDelays;
        m_allowedUids = newAllowedUids;
        m_ignoredApps = newIgnoredApps;
        m_specificIgnoreRules = newSpecificIgnoreRules;
        m_blockedDomains = newBlockedDomains;

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
        if (prefs.getBoolean(Rule.PREFERENCE_STRING_MANAGE_SYSTEM, false) != m_manage_system) {
            Log.w(TAG, "Had to update the preference system to set manage_system = " + Boolean.toString(m_manage_system));
            prefs.edit().putBoolean(Rule.PREFERENCE_STRING_MANAGE_SYSTEM, m_manage_system).apply();
        }

        prefs.edit().putBoolean(Rule.PREFERENCE_STRING_SHOW_USER, true).apply();
        prefs.edit().putBoolean(Rule.PREFERENCE_STRING_SHOW_SYSTEM, m_manage_system).apply();
    }

    boolean m_pleaseExpedite = false;
    public void enterExpeditePassword(Context context, String password) {
        boolean success = false;

        // Try all enacted rules for password success
        lock.readLock().lock();
        try {
            for (UniversalRule rule : m_allCurrentRules) {
                if (rule.type != PartnerRule.class)
                    continue;
                PartnerRule partnerRule = (PartnerRule) rule.rule;
                if (partnerRule.tryToUnlock(password)) {
                    success = true;
                    break;
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
            for (UniversalRule rule : m_allCurrentRules) {
                if (rule.type != RuleAndPackage.class) {
                    continue;
                }
                RuleAndPackage rap = (RuleAndPackage)rule.rule;
                if (rap.appliesToAccess(uid, daddrs)) {
                    ruletexts.add("- " + rule.getRuletext());
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
}

abstract class RuleWithDelayClassification {
    public abstract int getDelayToAdd(Context context, int main_delay);
    public abstract int getDelayToRemove(Context context, int main_delay);
    public abstract int getMajorCategory();
    public abstract int getMinorCategory();

    public Set<String> getActionsAfterAdd(Context context) {
        return null;
    }
    public Set<String> getActionsAfterRemove(Context context) {
        return null;
    }
}

class DelayRule extends RuleWithDelayClassification {
    private int m_delay;
    private String m_packageName;
    private static final int MINOR_CATEGORY_GLOBAL_DELAY = 100;
    private static final int MINOR_CATEGORY_PACKAGE_DELAY = 200;

    public DelayRule(int delay, String packageName) {
        m_delay = delay;
        m_packageName = packageName;
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

    public static UniversalRule parseRule(String ruletext) {
        // Ruletext match for a global delay rule
        Matcher m = Pattern.compile("delay (\\d+)").matcher(ruletext);
        if (m.matches()) {
            String rest = m.group(1);

            int delay;
            try {
                delay = Integer.parseInt(rest);
            } catch (NumberFormatException e) {
                return null;
            }
            return new UniversalRule(new DelayRule(delay, null), ruletext);
        }

        // Ruletext match for a package delay rule
        m = Pattern.compile("delay package:(\\S+) (\\d+)").matcher(ruletext);
        if (m.matches()) {
            String packageName = m.group(1);
            int delay;
            try {
                delay = Integer.parseInt(m.group(2));
            } catch (NumberFormatException e) {
                return null;
            }
            return new UniversalRule(new DelayRule(delay, packageName), ruletext);
        }

        return null;
    }

    public int getMajorCategory() {
        return UniversalRule.MAJOR_CATEGORY_DELAY;
    }

    public int getMinorCategory() {
        if (m_packageName == null) {
            return MINOR_CATEGORY_GLOBAL_DELAY;
        } else {
            return MINOR_CATEGORY_PACKAGE_DELAY;
        }
    }

    public String getPackageName() {
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

class AllowedPackageRule extends RuleWithDelayClassification {
    private static final String TAG = "Netguard.APRule";
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

    public static UniversalRule parseRule(Context context, String ruletext) {
        try {
            Bundle bundle = RulesManager.parseAllowTextToBundle(context, ruletext);

            if (bundle.containsKey("package") && !bundle.containsKey("host") && !bundle.containsKey("ip") && !bundle.containsKey("directip")) {
                // This is an allowed package
                String packagename = bundle.getString("package");
                boolean sticky = false;

                if (bundle.containsKey("sticky")) {
                    sticky = bundle.getBoolean("sticky");
                }

                return new UniversalRule(new AllowedPackageRule(packagename, sticky), ruletext);
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
                return new UniversalRule(new AllowedUidRule(uid, sticky), ruletext);
            } else if (bundle.containsKey("host") || bundle.containsKey("ip") || bundle.containsKey("directip")) {
                // This is a whitelisted URL
                RuleAndPackage newrule = RulesManager.parseTextToWhitelistRule(context, ruletext);
                if (newrule == null)
                    return null;
                return new UniversalRule(newrule, ruletext);
            }
        } catch (AssertionError e) {
            Log.e(TAG, "Got assertion error " + e);
            return null;
        }

        return null;
    }

    public int getMajorCategory() {
        return UniversalRule.MAJOR_CATEGORY_ALLOW;
    }

    public int getMinorCategory() {
        return 0;
    }

    public Set<String> getActionsAfterAdd(Context context) {
        return Collections.singleton("reload");
    }
    public Set<String> getActionsAfterRemove(Context context) {
        return Collections.singleton("reload");
    }
}

class AllowedUidRule extends RuleWithDelayClassification {
    private int m_uid;
    private boolean m_sticky;

    public AllowedUidRule(int uid, boolean sticky) {
        m_uid = uid;
        m_sticky = sticky;
    }

    public int getUid() {
        return m_uid;
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

    public int getMajorCategory() {
        return UniversalRule.MAJOR_CATEGORY_ALLOW;
    }

    public int getMinorCategory() {
        return 0;
    }

    public Set<String> getActionsAfterAdd(Context context) {
        return Collections.singleton("reload");
    }
    public Set<String> getActionsAfterRemove(Context context) {
        return Collections.singleton("reload");
    }
}

class FeatureRule extends RuleWithDelayClassification {
    private String m_featurename;
    private enum FeatureType {feature_restrictive, feature_permissive, feature_both};
    private FeatureType m_featuretype;
    private static final String[] restrictive_features = {"enabled",
                                                          "manage_system",
                                                          "capture_all_traffic"};
    private static final String[] permissive_features = {"allow_logging"};

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

    public Set<String> getActionsAfterAdd(Context context) {
        return Collections.singleton("reload");
    }
    public Set<String> getActionsAfterRemove(Context context) {
        return Collections.singleton("reload");
    }
}

// Rule class for partners who can expedite your rules
class PartnerRule extends RuleWithDelayClassification {
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

class IgnoreRule extends RuleWithDelayClassification {
    private static final String TAG = "NetGuard.IgnoreRule";
    private String m_packageName;
    private String m_hostName;

    public IgnoreRule(String packageName, String hostName) {
        m_packageName = packageName;
        m_hostName = hostName;
    }

    public int getDelayToAdd(Context context, int main_delay) {
        return 0;
    }
    public int getDelayToRemove(Context context, int main_delay) {
        return 0;
    }

    public static UniversalRule parseRule(String ruletext) {
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
        IgnoreRule ignoreRule = new IgnoreRule(packageName, hostName);
        return new UniversalRule(ignoreRule, ruletext);

    }

    public int getMajorCategory() {
        return UniversalRule.MAJOR_CATEGORY_IGNORE;
    }

    public int getMinorCategory() {
        return 0;
    }

    public String getPackageName() {
        return m_packageName;
    }

    public String getHostName() {
        return m_hostName;
    }
}

class BlockedDomainRule extends RuleWithDelayClassification {
    private String m_domainName;
    private boolean m_try;

    BlockedDomainRule(String domainName, boolean bTry) {
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

    public int getMajorCategory() {
        return UniversalRule.MAJOR_CATEGORY_BLOCK;
    }

    public int getMinorCategory() {
        return 0;
    }

    public String getDomainName() {
        return m_domainName;
    }

    public static UniversalRule parseRule(String ruletext)
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
        return new UniversalRule(new BlockedDomainRule(domainName, bTry), ruletext);
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

class UniversalRule {
    private static final String TAG = "NetGuard.UniversalRule";

    public static final int MAJOR_CATEGORY_DELAY = 100;
    public static final int MAJOR_CATEGORY_FEATURE = 200;
    public static final int MAJOR_CATEGORY_PARTNER = 300;
    public static final int MAJOR_CATEGORY_ALLOW = 400;
    public static final int MAJOR_CATEGORY_BLOCK = 450;
    public static final int MAJOR_CATEGORY_IGNORE = 500;

    public RuleWithDelayClassification rule;
    public Class type;
    private String m_ruletext;

    public UniversalRule(RuleWithDelayClassification newrule, String ruletext) {
        if (newrule == null)
            throw new AssertionError("Got a null rule for \"" + ruletext + "\"");
        rule = newrule;

        type = null;
        if (rule instanceof RuleAndPackage) {
            type = RuleAndPackage.class;
        } else if (rule instanceof DelayRule) {
            type = DelayRule.class;
        } else if (rule instanceof AllowedPackageRule) {
            type = AllowedPackageRule.class;
        } else if (rule instanceof FeatureRule) {
            type = FeatureRule.class;
        } else if (rule instanceof PartnerRule) {
            type = PartnerRule.class;
        } else if (rule instanceof AllowedUidRule) {
            type = AllowedUidRule.class;
        } else if (rule instanceof IgnoreRule) {
            type = IgnoreRule.class;
        } else if (rule instanceof BlockedDomainRule) {
            type = BlockedDomainRule.class;
        }

        if (type == null)
            throw new AssertionError("Unknown type for \"" + ruletext + "\"");

        m_ruletext = ruletext;
    }

    public static UniversalRule getRuleFromText(Context context, String ruletext) {
        Matcher m = Pattern.compile("([^\\s:]+) (.*)").matcher(ruletext);

        if (!m.matches()) {
            return null;
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
        } else if (category.equals("ignore")) {
            therule = IgnoreRule.parseRule(ruletext);
        } else if (category.equals("blockdomain")) {
            therule = BlockedDomainRule.parseRule(ruletext);
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

    public String getRuletext() {
        return m_ruletext;
    }
}
