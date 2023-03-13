package eu.faircode.netguard;

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
    private static final String TAG = "NetGuard.Database";

    public static final String ACTION_RULES_UPDATE = "eu.faircode.netguard.RULES_UPDATE";

    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

    private static volatile RulesManager global_rm = null;

    // Members that contain the current state of rules
    private boolean m_enabled = true;
    private int m_delay = 0;
    private Map<String, Boolean> m_allowedPackages = new HashMap<String, Boolean>();
    private List<RuleAndUid> m_whitelistRules = new ArrayList<RuleAndUid>();

    private long next_pending_time = 0;

    private long nextEnableToggle;
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
    private void putNewInt(Bundle bundle, String key, int value) {
        if (bundle.containsKey(key)) {
            throw new AssertionError("Already contains key " + key);
        }
        bundle.putInt(key, value);
    }
    private void putNewString(Bundle bundle, String key, String value) {
        if (bundle.containsKey(key)) {
            throw new AssertionError("Already contains key " + key);
        }
        bundle.putString(key, value);
    }

    // Somewhat general function to parse an allow rule into a bundle of all phrases
    private Bundle parseAllowTextToBundle(Context context, String text) {
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
    private RuleAndUid parseTextToWhitelistRule(Context context, String text) {
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

        for (RuleAndUid ruleanduid : m_whitelistRules) {
            results.add(ruleanduid);
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
            enactRule(context, ruletext, id);
            num_enacted += 1;
        }

        if (num_enacted > 0) {
            getAllEnactedRulesFromDb(context);
            if (!startup) {
                LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent(ActivityMain.ACTION_RULES_CHANGED));
            }
        }
    }

    private void enactRule(Context context, String ruletext, long id) {
        Log.w(TAG, "Enacting rule \"" + ruletext + "\" ID=" + Long.toString(id));

        DatabaseHelper dh = DatabaseHelper.getInstance(context);
        lock.writeLock().lock();
        try {
            dh.setRuleEnacted(Long.toString(id), 1);
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
    }

    public void setPackageAllowed(Context context, String packagename) {
        // Add a pending rule
        DatabaseHelper dh = DatabaseHelper.getInstance(context);

        String ruletext = "allow package:" + packagename;
        long enact_time = System.currentTimeMillis() + 100 * 1000;
        dh.addNewRule(ruletext, enact_time, 0);

        // Wake up when that rule should be applied
        setAlarmForPending(context);
    }

    private void getAllEnactedRulesFromDb(Context context) {
        DatabaseHelper dh = DatabaseHelper.getInstance(context);

        lock.writeLock().lock();

        Cursor cursor = dh.getEnactedRules();
        int col_ruletext = cursor.getColumnIndexOrThrow("ruletext");

        // If there are no delay rules, delay will be 0
        int newDelay = 0;
        Map<String, Boolean> newAllowedPackages = new HashMap<String, Boolean>();
        List<RuleAndUid> newWhitelistRules = new ArrayList<RuleAndUid>();

        while (cursor.moveToNext()) {
            String ruletext = cursor.getString(col_ruletext);

            try {
                Matcher m = Pattern.compile("([^\\s:]+) (.*)").matcher(ruletext);

                if (!m.matches()) {
                    throw new AssertionError("no category");
                }

                String category = m.group(1);
                String rest = m.group(2);

                if (category.equals("delay")) {
                    int thisdelay = Integer.parseInt(rest);

                    if (thisdelay > newDelay)
                        newDelay = thisdelay;
                } else if (category.equals("allow")) {
                    Bundle bundle = parseAllowTextToBundle(context, ruletext);
                    if (bundle.containsKey("package") && !bundle.containsKey("host") && !bundle.containsKey("ipv4")) {
                        // This is an allowed package
                        newAllowedPackages.put(bundle.getString("package"), false);
                    } else if (bundle.containsKey("host") || bundle.containsKey("ipv4")) {
                        // This is a whitelisted URL
                        RuleAndUid newrule = parseTextToWhitelistRule(context, ruletext);
                        if (newrule == null) {
                            throw new AssertionError("Didn't parse into a RuleAndUid");
                        }
                        newWhitelistRules.add(newrule);
                    }
                }
            } catch (Throwable e) {
                Log.e(TAG, "Ruletext \"" + ruletext + "\" didn't work: " + e.getLocalizedMessage());
            }
        }

        Log.w(TAG, "Got rules: new delay = " + Integer.toString(newDelay) + ", allowed packages = " + Integer.toString(newAllowedPackages.size()) + ", whitelisted URLs = " + Integer.toString(newWhitelistRules.size()));
        m_delay = newDelay;
        m_allowedPackages = newAllowedPackages;
        m_whitelistRules = newWhitelistRules;

        lock.writeLock().unlock();
    }
}
