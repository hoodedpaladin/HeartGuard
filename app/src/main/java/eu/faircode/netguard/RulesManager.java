package eu.faircode.netguard;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.os.Build;
import android.util.Log;

import androidx.annotation.GuardedBy;
import androidx.preference.PreferenceManager;

import java.util.Date;
import java.util.HashSet;
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

    private ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);

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
        lock.readLock().lock();

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

        lock.readLock().unlock();
    }

    public boolean getPreferenceFilter(Context context) {
        return true;
    }

    // HeartGuard - the rules change listeners get broadcasts of rules updates
    // (similar to OnSharedPreferenceChangeListener)
    private final Object mLock = new Object();
    private static final Object CONTENT = new Object();
    @GuardedBy("mLock")
    private final WeakHashMap<RulesManager.OnRuleChangeListener, Object> mListeners =
            new WeakHashMap<RulesManager.OnRuleChangeListener, Object>();

    public interface OnRuleChangeListener {
        void onRuleChanged(RulesManager rm, Context context, String key);
    }

    public void registerOnRuleChangeListener(RulesManager.OnRuleChangeListener listener) {
        synchronized(mLock) {
            mListeners.put(listener, CONTENT);
        }
    }

    public void unregisterOnRuleChangeListener(RulesManager.OnRuleChangeListener listener) {
        synchronized(mLock) {
            mListeners.remove(listener);
        }
    }

    private void notifyListeners(Context context, String key) {
        if (mListeners.size() < 1) {
            return;
        }

        // Make a copy of the hashed listeners, since that hash is weak
        Set<OnRuleChangeListener> listeners = new HashSet<RulesManager.OnRuleChangeListener>(mListeners.keySet());

        for (RulesManager.OnRuleChangeListener listener : listeners) {
            if (listener != null) {
                listener.onRuleChanged(this, context, key);
            }
        }
    }
}
