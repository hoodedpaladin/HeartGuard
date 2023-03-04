package eu.faircode.netguard;

/*
    This file is part of NetGuard.

    NetGuard is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    NetGuard is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with NetGuard.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2015-2019 by Marcel Bokhorst (M66B)
*/

import android.Manifest;
import android.annotation.TargetApi;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.Uri;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.preference.EditTextPreference;
import android.preference.ListPreference;
import android.preference.MultiSelectListPreference;
import android.preference.Preference;
import android.preference.PreferenceFragment;
import android.preference.PreferenceGroup;
import android.preference.PreferenceScreen;
import android.preference.TwoStatePreference;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextUtils;
import android.text.style.ImageSpan;
import android.util.Log;
import android.util.Xml;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.NavUtils;
import androidx.core.util.PatternsCompat;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;
import androidx.preference.PreferenceManager;

import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.XMLReader;
import org.xml.sax.helpers.DefaultHandler;
import org.xmlpull.v1.XmlSerializer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParserFactory;

public class ActivitySettings extends AppCompatActivity implements SharedPreferences.OnSharedPreferenceChangeListener {
    private static final String TAG = "NetGuard.Settings";

    private boolean running = false;

    private static final int REQUEST_HOSTS = 3;
    private static final int REQUEST_HOSTS_APPEND = 4;
    private static final int REQUEST_CALL = 5;

    private AlertDialog dialogFilter = null;

    private static final Intent INTENT_VPN_SETTINGS = new Intent("android.net.vpn.SETTINGS");

    protected void onCreate(Bundle savedInstanceState) {
        Util.setTheme(this);
        super.onCreate(savedInstanceState);
        getFragmentManager().beginTransaction().replace(android.R.id.content, new FragmentSettings()).commit();
        getSupportActionBar().setTitle(R.string.menu_settings);
        running = true;
    }

    private PreferenceScreen getPreferenceScreen() {
        return ((PreferenceFragment) getFragmentManager().findFragmentById(android.R.id.content)).getPreferenceScreen();
    }

    @Override
    protected void onPostCreate(Bundle savedInstanceState) {
        super.onPostCreate(savedInstanceState);
        final PreferenceScreen screen = getPreferenceScreen();
        final SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        PreferenceGroup cat_options = (PreferenceGroup) ((PreferenceGroup) screen.findPreference("screen_options")).findPreference("category_options");
        PreferenceGroup cat_network = (PreferenceGroup) ((PreferenceGroup) screen.findPreference("screen_network_options")).findPreference("category_network_options");
        PreferenceGroup cat_advanced = (PreferenceGroup) ((PreferenceGroup) screen.findPreference("screen_advanced_options")).findPreference("category_advanced_options");
        PreferenceGroup cat_stats = (PreferenceGroup) ((PreferenceGroup) screen.findPreference("screen_stats")).findPreference("category_stats");
        PreferenceGroup cat_backup = (PreferenceGroup) ((PreferenceGroup) screen.findPreference("screen_backup")).findPreference("category_backup");

        // Handle auto enable
        Preference pref_auto_enable = screen.findPreference("auto_enable");
        pref_auto_enable.setTitle(getString(R.string.setting_auto, prefs.getString("auto_enable", "0")));

        // Handle screen delay
        Preference pref_screen_delay = screen.findPreference("screen_delay");
        pref_screen_delay.setTitle(getString(R.string.setting_delay, prefs.getString("screen_delay", "0")));

        // Handle theme
        Preference pref_screen_theme = screen.findPreference("theme");
        String theme = prefs.getString("theme", "teal");
        String[] themeNames = getResources().getStringArray(R.array.themeNames);
        String[] themeValues = getResources().getStringArray(R.array.themeValues);
        for (int i = 0; i < themeNames.length; i++)
            if (theme.equals(themeValues[i])) {
                pref_screen_theme.setTitle(getString(R.string.setting_theme, themeNames[i]));
                break;
            }

        // Wi-Fi home
        MultiSelectListPreference pref_wifi_homes = (MultiSelectListPreference) screen.findPreference("wifi_homes");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1)
            cat_network.removePreference(pref_wifi_homes);
        else {
            Set<String> ssids = prefs.getStringSet("wifi_homes", new HashSet<String>());
            if (ssids.size() > 0)
                pref_wifi_homes.setTitle(getString(R.string.setting_wifi_home, TextUtils.join(", ", ssids)));
            else
                pref_wifi_homes.setTitle(getString(R.string.setting_wifi_home, "-"));

            WifiManager wm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            List<CharSequence> listSSID = new ArrayList<>();
            List<WifiConfiguration> configs = wm.getConfiguredNetworks();
            if (configs != null)
                for (WifiConfiguration config : configs)
                    listSSID.add(config.SSID == null ? "NULL" : config.SSID);
            for (String ssid : ssids)
                if (!listSSID.contains(ssid))
                    listSSID.add(ssid);
            pref_wifi_homes.setEntries(listSSID.toArray(new CharSequence[0]));
            pref_wifi_homes.setEntryValues(listSSID.toArray(new CharSequence[0]));
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            TwoStatePreference pref_handover =
                    (TwoStatePreference) screen.findPreference("handover");
            cat_advanced.removePreference(pref_handover);
        }

        Preference pref_reset_usage = screen.findPreference("reset_usage");
        pref_reset_usage.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                Util.areYouSure(ActivitySettings.this, R.string.setting_reset_usage, new Util.DoubtListener() {
                    @Override
                    public void onSure() {
                        new AsyncTask<Object, Object, Throwable>() {
                            @Override
                            protected Throwable doInBackground(Object... objects) {
                                try {
                                    DatabaseHelper.getInstance(ActivitySettings.this).resetUsage(-1);
                                    return null;
                                } catch (Throwable ex) {
                                    return ex;
                                }
                            }

                            @Override
                            protected void onPostExecute(Throwable ex) {
                                if (ex == null)
                                    Toast.makeText(ActivitySettings.this, R.string.msg_completed, Toast.LENGTH_LONG).show();
                                else
                                    Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
                            }
                        }.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
                    }
                });
                return false;
            }
        });

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            TwoStatePreference pref_reload_onconnectivity =
                    (TwoStatePreference) screen.findPreference("reload_onconnectivity");
            pref_reload_onconnectivity.setChecked(true);
            pref_reload_onconnectivity.setEnabled(false);
        }

        // Handle port forwarding
        Preference pref_forwarding = screen.findPreference("forwarding");
        pref_forwarding.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                startActivity(new Intent(ActivitySettings.this, ActivityForwarding.class));
                return true;
            }
        });

        boolean can = Util.canFilter(this);
        TwoStatePreference pref_log_app = (TwoStatePreference) screen.findPreference(Rule.PREFERENCE_STRING_LOG_APP);
        pref_log_app.setEnabled(can);
        if (!can) {
            pref_log_app.setSummary(R.string.msg_unavailable);
        }

        // VPN parameters
        screen.findPreference("vpn4").setTitle(getString(R.string.setting_vpn4, prefs.getString("vpn4", "10.1.10.1")));
        screen.findPreference("vpn6").setTitle(getString(R.string.setting_vpn6, prefs.getString("vpn6", "fd00:1:fd00:1:fd00:1:fd00:1")));
        EditTextPreference pref_dns1 = (EditTextPreference) screen.findPreference("dns");
        EditTextPreference pref_dns2 = (EditTextPreference) screen.findPreference("dns2");
        EditTextPreference pref_validate = (EditTextPreference) screen.findPreference("validate");
        EditTextPreference pref_ttl = (EditTextPreference) screen.findPreference("ttl");
        pref_dns1.setTitle(getString(R.string.setting_dns, prefs.getString("dns", "-")));
        pref_dns2.setTitle(getString(R.string.setting_dns, prefs.getString("dns2", "-")));
        pref_validate.setTitle(getString(R.string.setting_validate, prefs.getString("validate", "www.google.com")));
        pref_ttl.setTitle(getString(R.string.setting_ttl, prefs.getString("ttl", "259200")));

        // SOCKS5 parameters
        screen.findPreference("socks5_addr").setTitle(getString(R.string.setting_socks5_addr, prefs.getString("socks5_addr", "-")));
        screen.findPreference("socks5_port").setTitle(getString(R.string.setting_socks5_port, prefs.getString("socks5_port", "-")));
        screen.findPreference("socks5_username").setTitle(getString(R.string.setting_socks5_username, prefs.getString("socks5_username", "-")));
        screen.findPreference("socks5_password").setTitle(getString(R.string.setting_socks5_password, TextUtils.isEmpty(prefs.getString("socks5_username", "")) ? "-" : "*****"));

        // PCAP parameters
        screen.findPreference("pcap_record_size").setTitle(getString(R.string.setting_pcap_record_size, prefs.getString("pcap_record_size", "64")));
        screen.findPreference("pcap_file_size").setTitle(getString(R.string.setting_pcap_file_size, prefs.getString("pcap_file_size", "2")));

        // Watchdog
        screen.findPreference("watchdog").setTitle(getString(R.string.setting_watchdog, prefs.getString("watchdog", "0")));

        // Show resolved
        Preference pref_show_resolved = screen.findPreference("show_resolved");
        if (Util.isPlayStoreInstall(this))
            cat_advanced.removePreference(pref_show_resolved);
        else
            pref_show_resolved.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    startActivity(new Intent(ActivitySettings.this, ActivityDns.class));
                    return true;
                }
            });

        // Handle stats
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N)
            cat_stats.removePreference(screen.findPreference("show_top"));
        EditTextPreference pref_stats_frequency = (EditTextPreference) screen.findPreference("stats_frequency");
        EditTextPreference pref_stats_samples = (EditTextPreference) screen.findPreference("stats_samples");
        pref_stats_frequency.setTitle(getString(R.string.setting_stats_frequency, prefs.getString("stats_frequency", "1000")));
        pref_stats_samples.setTitle(getString(R.string.setting_stats_samples, prefs.getString("stats_samples", "90")));

        // Hosts file settings
        Preference pref_block_domains = screen.findPreference("use_hosts");
        EditTextPreference pref_rcode = (EditTextPreference) screen.findPreference("rcode");
        Preference pref_hosts_import = screen.findPreference("hosts_import");
        Preference pref_hosts_import_append = screen.findPreference("hosts_import_append");
        EditTextPreference pref_hosts_url = (EditTextPreference) screen.findPreference("hosts_url");
        final Preference pref_hosts_download = screen.findPreference("hosts_download");

        pref_rcode.setTitle(getString(R.string.setting_rcode, prefs.getString("rcode", "3")));

        if (Util.isPlayStoreInstall(this) || !Util.hasValidFingerprint(this))
            cat_options.removePreference(screen.findPreference("update_check"));

        if (Util.isPlayStoreInstall(this)) {
            Log.i(TAG, "Play store install");
            cat_advanced.removePreference(pref_block_domains);
            cat_advanced.removePreference(pref_rcode);
            cat_advanced.removePreference(pref_forwarding);
            cat_backup.removePreference(pref_hosts_import);
            cat_backup.removePreference(pref_hosts_import_append);
            cat_backup.removePreference(pref_hosts_url);
            cat_backup.removePreference(pref_hosts_download);

        } else {
            String last_import = prefs.getString("hosts_last_import", null);
            String last_download = prefs.getString("hosts_last_download", null);
            if (last_import != null)
                pref_hosts_import.setSummary(getString(R.string.msg_import_last, last_import));
            if (last_download != null)
                pref_hosts_download.setSummary(getString(R.string.msg_download_last, last_download));

            // Handle hosts import
            // https://github.com/Free-Software-for-Android/AdAway/wiki/HostsSources
            pref_hosts_import.setEnabled(getIntentOpenHosts().resolveActivity(getPackageManager()) != null);
            pref_hosts_import.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    startActivityForResult(getIntentOpenHosts(), ActivitySettings.REQUEST_HOSTS);
                    return true;
                }
            });
            pref_hosts_import_append.setEnabled(pref_hosts_import.isEnabled());
            pref_hosts_import_append.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    startActivityForResult(getIntentOpenHosts(), ActivitySettings.REQUEST_HOSTS_APPEND);
                    return true;
                }
            });

            // Handle hosts file download
            pref_hosts_url.setSummary(pref_hosts_url.getText());
            pref_hosts_download.setOnPreferenceClickListener(new Preference.OnPreferenceClickListener() {
                @Override
                public boolean onPreferenceClick(Preference preference) {
                    final File tmp = new File(getFilesDir(), "hosts.tmp");
                    final File hosts = new File(getFilesDir(), "hosts.txt");

                    EditTextPreference pref_hosts_url = (EditTextPreference) screen.findPreference("hosts_url");
                    String hosts_url = pref_hosts_url.getText();
                    if ("https://www.netguard.me/hosts".equals(hosts_url))
                        hosts_url = BuildConfig.HOSTS_FILE_URI;

                    try {
                        new DownloadTask(ActivitySettings.this, new URL(hosts_url), tmp, new DownloadTask.Listener() {
                            @Override
                            public void onCompleted() {
                                if (hosts.exists())
                                    hosts.delete();
                                tmp.renameTo(hosts);

                                String last = SimpleDateFormat.getDateTimeInstance().format(new Date().getTime());
                                prefs.edit().putString("hosts_last_download", last).apply();

                                if (running) {
                                    pref_hosts_download.setSummary(getString(R.string.msg_download_last, last));
                                    Toast.makeText(ActivitySettings.this, R.string.msg_downloaded, Toast.LENGTH_LONG).show();
                                }

                                ServiceSinkhole.reload("hosts file download", ActivitySettings.this, false);
                            }

                            @Override
                            public void onCancelled() {
                                if (tmp.exists())
                                    tmp.delete();
                            }

                            @Override
                            public void onException(Throwable ex) {
                                if (tmp.exists())
                                    tmp.delete();

                                if (running)
                                    Toast.makeText(ActivitySettings.this, ex.getMessage(), Toast.LENGTH_LONG).show();
                            }
                        }).executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
                    } catch (MalformedURLException ex) {
                        Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
                    }
                    return true;
                }
            });
        }

        // Development
        if (!Util.isDebuggable(this))
            screen.removePreference(screen.findPreference("screen_development"));

        // Handle technical info
        Preference.OnPreferenceClickListener listener = new Preference.OnPreferenceClickListener() {
            @Override
            public boolean onPreferenceClick(Preference preference) {
                updateTechnicalInfo();
                return true;
            }
        };

        // Technical info
        Preference pref_technical_info = screen.findPreference("technical_info");
        Preference pref_technical_network = screen.findPreference("technical_network");
        pref_technical_info.setEnabled(INTENT_VPN_SETTINGS.resolveActivity(this.getPackageManager()) != null);
        pref_technical_info.setIntent(INTENT_VPN_SETTINGS);
        pref_technical_info.setOnPreferenceClickListener(listener);
        pref_technical_network.setOnPreferenceClickListener(listener);
        updateTechnicalInfo();

        markPro(screen.findPreference("theme"), ActivityPro.SKU_THEME);
        markPro(screen.findPreference("install"), ActivityPro.SKU_NOTIFY);
        markPro(screen.findPreference("show_stats"), ActivityPro.SKU_SPEED);
    }

    @Override
    protected void onResume() {
        super.onResume();

        checkPermissions(null);

        // Listen for preference changes
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.registerOnSharedPreferenceChangeListener(this);

        // Listen for interactive state changes
        IntentFilter ifInteractive = new IntentFilter();
        ifInteractive.addAction(Intent.ACTION_SCREEN_ON);
        ifInteractive.addAction(Intent.ACTION_SCREEN_OFF);
        registerReceiver(interactiveStateReceiver, ifInteractive);

        // Listen for connectivity updates
        IntentFilter ifConnectivity = new IntentFilter();
        ifConnectivity.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        registerReceiver(connectivityChangedReceiver, ifConnectivity);
    }

    @Override
    protected void onPause() {
        super.onPause();

        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
        prefs.unregisterOnSharedPreferenceChangeListener(this);

        unregisterReceiver(interactiveStateReceiver);
        unregisterReceiver(connectivityChangedReceiver);
    }

    @Override
    protected void onDestroy() {
        running = false;
        if (dialogFilter != null) {
            dialogFilter.dismiss();
            dialogFilter = null;
        }
        super.onDestroy();
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:
                Log.i(TAG, "Up");
                NavUtils.navigateUpFromSameTask(this);
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }

    @Override
    @TargetApi(Build.VERSION_CODES.M)
    public void onSharedPreferenceChanged(SharedPreferences prefs, String name) {
        // Pro features
        if ("theme".equals(name)) {
            if (!"teal".equals(prefs.getString(name, "teal")) && !IAB.isPurchased(ActivityPro.SKU_THEME, this)) {
                prefs.edit().putString(name, "teal").apply();
                ((ListPreference) getPreferenceScreen().findPreference(name)).setValue("teal");
                startActivity(new Intent(this, ActivityPro.class));
                return;
            }
        } else if ("install".equals(name)) {
            if (prefs.getBoolean(name, false) && !IAB.isPurchased(ActivityPro.SKU_NOTIFY, this)) {
                prefs.edit().putBoolean(name, false).apply();
                ((TwoStatePreference) getPreferenceScreen().findPreference(name)).setChecked(false);
                startActivity(new Intent(this, ActivityPro.class));
                return;
            }
        } else if ("show_stats".equals(name)) {
            if (prefs.getBoolean(name, false) && !IAB.isPurchased(ActivityPro.SKU_SPEED, this)) {
                prefs.edit().putBoolean(name, false).apply();
                startActivity(new Intent(this, ActivityPro.class));
                return;
            }
            ((TwoStatePreference) getPreferenceScreen().findPreference(name)).setChecked(prefs.getBoolean(name, false));
        }

        Object value = prefs.getAll().get(name);
        if (value instanceof String && "".equals(value))
            prefs.edit().remove(name).apply();

        // Dependencies
        if (Rule.PREFERENCE_STRING_SCREEN_ON.equals(name))
            ServiceSinkhole.reload("changed " + Rule.PREFERENCE_STRING_SCREEN_ON, this, false);

        else if (Rule.PREFERENCE_STRING_WHITELIST_WIFI.equals(name) ||
                Rule.PREFERENCE_STRING_SCREEN_WIFI.equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if (Rule.PREFERENCE_STRING_WHITELIST_OTHER.equals(name) ||
                Rule.PREFERENCE_STRING_SCREEN_OTHER.equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if (Rule.PREFERENCE_STRING_WHITELIST_ROAMING.equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if ("auto_enable".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_auto, prefs.getString(name, "0")));

        else if ("screen_delay".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_delay, prefs.getString(name, "0")));

        else if ("theme".equals(name) || "dark_theme".equals(name))
            recreate();

        else if ("subnet".equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if ("tethering".equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if ("lan".equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if ("ip6".equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if ("wifi_homes".equals(name)) {
            MultiSelectListPreference pref_wifi_homes = (MultiSelectListPreference) getPreferenceScreen().findPreference(name);
            Set<String> ssid = prefs.getStringSet(name, new HashSet<String>());
            if (ssid.size() > 0)
                pref_wifi_homes.setTitle(getString(R.string.setting_wifi_home, TextUtils.join(", ", ssid)));
            else
                pref_wifi_homes.setTitle(getString(R.string.setting_wifi_home, "-"));
            ServiceSinkhole.reload("changed " + name, this, false);

        } else if ("use_metered".equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if ("unmetered_2g".equals(name) ||
                "unmetered_3g".equals(name) ||
                "unmetered_4g".equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if ("national_roaming".equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if ("eu_roaming".equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if ("disable_on_call".equals(name)) {
            if (prefs.getBoolean(name, false)) {
                if (checkPermissions(name))
                    ServiceSinkhole.reload("changed " + name, this, false);
            } else
                ServiceSinkhole.reload("changed " + name, this, false);

        } else if (Rule.PREFERENCE_STRING_LOCKDOWN_WIFI.equals(name) || Rule.PREFERENCE_STRING_LOCKDOWN_OTHER.equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if (Rule.PREFERENCE_STRING_MANAGE_SYSTEM.equals(name)) {
            boolean manage = prefs.getBoolean(name, false);
            if (!manage)
                prefs.edit().putBoolean(Rule.PREFERENCE_STRING_SHOW_USER, true).apply();
            prefs.edit().putBoolean(Rule.PREFERENCE_STRING_SHOW_SYSTEM, manage).apply();
            ServiceSinkhole.reload("changed " + name, this, false);

        } else if (Rule.PREFERENCE_STRING_LOG_APP.equals(name)) {
            Intent ruleset = new Intent(ActivityMain.ACTION_RULES_CHANGED);
            LocalBroadcastManager.getInstance(this).sendBroadcast(ruleset);
            ServiceSinkhole.reload("changed " + Rule.PREFERENCE_STRING_LOG_APP, this, false);

        } else if ("notify_access".equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if ("use_hosts".equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if ("vpn4".equals(name)) {
            String vpn4 = prefs.getString(name, null);
            try {
                checkAddress(vpn4, false);
                prefs.edit().putString(name, vpn4.trim()).apply();
            } catch (Throwable ex) {
                prefs.edit().remove(name).apply();
                ((EditTextPreference) getPreferenceScreen().findPreference(name)).setText(null);
                if (!TextUtils.isEmpty(vpn4))
                    Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
            getPreferenceScreen().findPreference(name).setTitle(
                    getString(R.string.setting_vpn4, prefs.getString(name, "10.1.10.1")));
            ServiceSinkhole.reload("changed " + name, this, false);

        } else if ("vpn6".equals(name)) {
            String vpn6 = prefs.getString(name, null);
            try {
                checkAddress(vpn6, false);
                prefs.edit().putString(name, vpn6.trim()).apply();
            } catch (Throwable ex) {
                prefs.edit().remove(name).apply();
                ((EditTextPreference) getPreferenceScreen().findPreference(name)).setText(null);
                if (!TextUtils.isEmpty(vpn6))
                    Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
            getPreferenceScreen().findPreference(name).setTitle(
                    getString(R.string.setting_vpn6, prefs.getString(name, "fd00:1:fd00:1:fd00:1:fd00:1")));
            ServiceSinkhole.reload("changed " + name, this, false);

        } else if ("dns".equals(name) || "dns2".equals(name)) {
            String dns = prefs.getString(name, null);
            try {
                checkAddress(dns, true);
                prefs.edit().putString(name, dns.trim()).apply();
            } catch (Throwable ex) {
                prefs.edit().remove(name).apply();
                ((EditTextPreference) getPreferenceScreen().findPreference(name)).setText(null);
                if (!TextUtils.isEmpty(dns))
                    Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
            getPreferenceScreen().findPreference(name).setTitle(
                    getString(R.string.setting_dns, prefs.getString(name, "-")));
            ServiceSinkhole.reload("changed " + name, this, false);

        } else if ("validate".equals(name)) {
            String host = prefs.getString(name, "www.google.com");
            try {
                checkDomain(host);
                prefs.edit().putString(name, host.trim()).apply();
            } catch (Throwable ex) {
                prefs.edit().remove(name).apply();
                ((EditTextPreference) getPreferenceScreen().findPreference(name)).setText(null);
                if (!TextUtils.isEmpty(host))
                    Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
            getPreferenceScreen().findPreference(name).setTitle(
                    getString(R.string.setting_validate, prefs.getString(name, "www.google.com")));
            ServiceSinkhole.reload("changed " + name, this, false);

        } else if ("ttl".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(
                    getString(R.string.setting_ttl, prefs.getString(name, "259200")));

        else if ("rcode".equals(name)) {
            getPreferenceScreen().findPreference(name).setTitle(
                    getString(R.string.setting_rcode, prefs.getString(name, "3")));
            ServiceSinkhole.reload("changed " + name, this, false);

        } else if ("socks5_enabled".equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);

        else if ("socks5_addr".equals(name)) {
            String socks5_addr = prefs.getString(name, null);
            try {
                if (!TextUtils.isEmpty(socks5_addr) && !Util.isNumericAddress(socks5_addr))
                    throw new IllegalArgumentException("Bad address");
            } catch (Throwable ex) {
                prefs.edit().remove(name).apply();
                ((EditTextPreference) getPreferenceScreen().findPreference(name)).setText(null);
                if (!TextUtils.isEmpty(socks5_addr))
                    Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
            }
            getPreferenceScreen().findPreference(name).setTitle(
                    getString(R.string.setting_socks5_addr, prefs.getString(name, "-")));
            ServiceSinkhole.reload("changed " + name, this, false);

        } else if ("socks5_port".equals(name)) {
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_socks5_port, prefs.getString(name, "-")));
            ServiceSinkhole.reload("changed " + name, this, false);

        } else if ("socks5_username".equals(name)) {
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_socks5_username, prefs.getString(name, "-")));
            ServiceSinkhole.reload("changed " + name, this, false);

        } else if ("socks5_password".equals(name)) {
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_socks5_password, TextUtils.isEmpty(prefs.getString(name, "")) ? "-" : "*****"));
            ServiceSinkhole.reload("changed " + name, this, false);

        } else if ("pcap_record_size".equals(name) || "pcap_file_size".equals(name)) {
            if ("pcap_record_size".equals(name))
                getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_pcap_record_size, prefs.getString(name, "64")));
            else
                getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_pcap_file_size, prefs.getString(name, "2")));

            ServiceSinkhole.setPcap(false, this);

            File pcap_file = new File(getDir("data", MODE_PRIVATE), "netguard.pcap");
            if (pcap_file.exists() && !pcap_file.delete())
                Log.w(TAG, "Delete PCAP failed");

            if (prefs.getBoolean("pcap", false))
                ServiceSinkhole.setPcap(true, this);

        } else if ("watchdog".equals(name)) {
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_watchdog, prefs.getString(name, "0")));
            ServiceSinkhole.reload("changed " + name, this, false);

        } else if ("show_stats".equals(name))
            ServiceSinkhole.reloadStats("changed " + name, this);

        else if ("stats_frequency".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_stats_frequency, prefs.getString(name, "1000")));

        else if ("stats_samples".equals(name))
            getPreferenceScreen().findPreference(name).setTitle(getString(R.string.setting_stats_samples, prefs.getString(name, "90")));

        else if ("hosts_url".equals(name))
            getPreferenceScreen().findPreference(name).setSummary(prefs.getString(name, BuildConfig.HOSTS_FILE_URI));

        else if ("loglevel".equals(name))
            ServiceSinkhole.reload("changed " + name, this, false);
    }

    @TargetApi(Build.VERSION_CODES.M)
    private boolean checkPermissions(String name) {
        PreferenceScreen screen = getPreferenceScreen();
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        // Check if permission was revoked
        if ((name == null || "disable_on_call".equals(name)) && prefs.getBoolean("disable_on_call", false))
            if (!Util.hasPhoneStatePermission(this)) {
                prefs.edit().putBoolean("disable_on_call", false).apply();
                ((TwoStatePreference) screen.findPreference("disable_on_call")).setChecked(false);

                requestPermissions(new String[]{Manifest.permission.READ_PHONE_STATE}, REQUEST_CALL);

                if (name != null)
                    return false;
            }

        return true;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        PreferenceScreen screen = getPreferenceScreen();
        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);

        boolean granted = (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED);

        if (requestCode == REQUEST_CALL) {
            prefs.edit().putBoolean("disable_on_call", granted).apply();
            ((TwoStatePreference) screen.findPreference("disable_on_call")).setChecked(granted);
        }

        if (granted)
            ServiceSinkhole.reload("permission granted", this, false);
    }

    private void checkAddress(String address, boolean allow_local) throws IllegalArgumentException, UnknownHostException {
        if (address != null)
            address = address.trim();
        if (TextUtils.isEmpty(address))
            throw new IllegalArgumentException("Bad address");
        if (!Util.isNumericAddress(address))
            throw new IllegalArgumentException("Bad address");
        if (!allow_local) {
            InetAddress iaddr = InetAddress.getByName(address);
            if (iaddr.isLoopbackAddress() || iaddr.isAnyLocalAddress())
                throw new IllegalArgumentException("Bad address");
        }
    }

    private void checkDomain(String address) throws IllegalArgumentException, UnknownHostException {
        if (address != null)
            address = address.trim();
        if (TextUtils.isEmpty(address))
            throw new IllegalArgumentException("Bad address");
        if (Util.isNumericAddress(address))
            throw new IllegalArgumentException("Bad address");
        if (!PatternsCompat.DOMAIN_NAME.matcher(address).matches())
            throw new IllegalArgumentException("Bad address");
    }

    private BroadcastReceiver interactiveStateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Util.logExtras(intent);
            updateTechnicalInfo();
        }
    };

    private BroadcastReceiver connectivityChangedReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            Util.logExtras(intent);
            updateTechnicalInfo();
        }
    };

    private void markPro(Preference pref, String sku) {
        if (sku == null || !IAB.isPurchased(sku, this)) {
            SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
            boolean dark = prefs.getBoolean("dark_theme", false);
            SpannableStringBuilder ssb = new SpannableStringBuilder("  " + pref.getTitle());
            ssb.setSpan(new ImageSpan(this, dark ? R.drawable.ic_shopping_cart_white_24dp : R.drawable.ic_shopping_cart_black_24dp), 0, 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            pref.setTitle(ssb);
        }
    }

    private void updateTechnicalInfo() {
        PreferenceScreen screen = getPreferenceScreen();
        Preference pref_technical_info = screen.findPreference("technical_info");
        Preference pref_technical_network = screen.findPreference("technical_network");

        pref_technical_info.setSummary(Util.getGeneralInfo(this));
        pref_technical_network.setSummary(Util.getNetworkInfo(this));
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, final Intent data) {
        Log.i(TAG, "onActivityResult request=" + requestCode + " result=" + requestCode + " ok=" + (resultCode == RESULT_OK));
        if (requestCode == REQUEST_HOSTS) {
            if (resultCode == RESULT_OK && data != null)
                handleHosts(data, false);

        } else if (requestCode == REQUEST_HOSTS_APPEND) {
            if (resultCode == RESULT_OK && data != null)
                handleHosts(data, true);

        } else {
            Log.w(TAG, "Unknown activity result request=" + requestCode);
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    private Intent getIntentOpenHosts() {
        Intent intent;
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT)
            intent = new Intent(Intent.ACTION_GET_CONTENT);
        else
            intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*"); // text/plain
        return intent;
    }

    private void handleHosts(final Intent data, final boolean append) {
        new AsyncTask<Object, Object, Throwable>() {
            @Override
            protected Throwable doInBackground(Object... objects) {
                File hosts = new File(getFilesDir(), "hosts.txt");

                FileOutputStream out = null;
                InputStream in = null;
                try {
                    Log.i(TAG, "Reading URI=" + data.getData());
                    ContentResolver resolver = getContentResolver();
                    String[] streamTypes = resolver.getStreamTypes(data.getData(), "*/*");
                    String streamType = (streamTypes == null || streamTypes.length == 0 ? "*/*" : streamTypes[0]);
                    AssetFileDescriptor descriptor = resolver.openTypedAssetFileDescriptor(data.getData(), streamType, null);
                    in = descriptor.createInputStream();
                    out = new FileOutputStream(hosts, append);

                    int len;
                    long total = 0;
                    byte[] buf = new byte[4096];
                    while ((len = in.read(buf)) > 0) {
                        out.write(buf, 0, len);
                        total += len;
                    }
                    Log.i(TAG, "Copied bytes=" + total);

                    return null;
                } catch (Throwable ex) {
                    Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                    return ex;
                } finally {
                    if (out != null)
                        try {
                            out.close();
                        } catch (IOException ex) {
                            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        }
                    if (in != null)
                        try {
                            in.close();
                        } catch (IOException ex) {
                            Log.e(TAG, ex.toString() + "\n" + Log.getStackTraceString(ex));
                        }
                }
            }

            @Override
            protected void onPostExecute(Throwable ex) {
                if (running) {
                    if (ex == null) {
                        SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(ActivitySettings.this);
                        String last = SimpleDateFormat.getDateTimeInstance().format(new Date().getTime());
                        prefs.edit().putString("hosts_last_import", last).apply();

                        if (running) {
                            getPreferenceScreen().findPreference("hosts_import").setSummary(getString(R.string.msg_import_last, last));
                            Toast.makeText(ActivitySettings.this, R.string.msg_completed, Toast.LENGTH_LONG).show();
                        }

                        ServiceSinkhole.reload("hosts import", ActivitySettings.this, false);
                    } else
                        Toast.makeText(ActivitySettings.this, ex.toString(), Toast.LENGTH_LONG).show();
                }
            }
        }.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
    }
}
