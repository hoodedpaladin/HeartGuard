package eu.faircode.netguard;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.database.Cursor;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.CursorAdapter;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.PopupMenu;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import java.text.SimpleDateFormat;
import java.util.Date;

// Activity to display all current/pending rules in a window
// Much implementation copied from ActivityForwarding (because why not)

public class ActivityRulesList extends AppCompatActivity {
    private static final String TAG = "NetGuard.ActRulesList";

    private ListView lvRulesList;
    private AdapterRulesList adapter;

    private DatabaseHelper.RuleChangedListener listener = new DatabaseHelper.RuleChangedListener() {
        @Override
        public void onChanged() {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    if (adapter != null)
                        adapter.changeCursor(DatabaseHelper.getInstance(ActivityRulesList.this).getAllRules());
                }
            });
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Util.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.rules_list);

        getSupportActionBar().setTitle(R.string.rules_list);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        lvRulesList = findViewById(R.id.lvRulesList);
        adapter = new AdapterRulesList(this, DatabaseHelper.getInstance(this).getAllRules());
        lvRulesList.setAdapter(adapter);
        lvRulesList.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                Cursor cursor = (Cursor)adapter.getItem(position);

                int colRuleText = cursor.getColumnIndexOrThrow("ruletext");
                int colEnacted = cursor.getColumnIndexOrThrow("enacted");

                final String ruletext = cursor.getString(colRuleText);
                boolean enacted = cursor.getInt(colEnacted) != 0;
                //Log.w(TAG, "clicked id " + Long.toString(id) + " or, from cursor, " + Long.toString(otherid));
                PopupMenu popup = new PopupMenu(ActivityRulesList.this, view);
                popup.inflate(R.menu.rules_list_popup);
                if (!enacted) {
                    popup.getMenu().removeItem(R.id.menu_ruleslist_popup_delete);
                }
                if (enacted) {
                    popup.getMenu().removeItem(R.id.menu_ruleslist_popup_abandon);
                }
                popup.getMenu().findItem(R.id.menu_ruleslist_popup_title).setTitle(ruletext);
                popup.setOnMenuItemClickListener(new PopupMenu.OnMenuItemClickListener() {
                    @Override
                    public boolean onMenuItemClick(MenuItem menuItem) {
                        int menuitem = menuItem.getItemId();
                        if (menuitem == R.id.menu_ruleslist_popup_delete) {
                            String message = ActivityRulesList.this.getString(R.string.confirm_delete_rule, ruletext);
                            Util.areYouSure(ActivityRulesList.this, message, new Util.DoubtListener() {
                                @Override
                                public void onSure() {
                                    try {
                                        RulesManager.getInstance(ActivityRulesList.this).queueRuleText(ActivityRulesList.this, "- " + ruletext);
                                    } catch (Throwable e) {
                                        Log.e(TAG, "Got exception: " + e);
                                    }
                                }
                            });
                            return true;
                        } else if (menuitem == R.id.menu_ruleslist_popup_abandon) {
                            String message = ActivityRulesList.this.getString(R.string.confirm_abandon_rule, ruletext);
                            Util.areYouSure(ActivityRulesList.this, message, new Util.DoubtListener() {
                                @Override
                                public void onSure() {
                                    try {
                                        RulesManager.getInstance(ActivityRulesList.this).queueRuleText(ActivityRulesList.this, "abandon " + ruletext);
                                    } catch (Throwable e) {
                                        Log.e(TAG, "Got exception: " + e);
                                    }
                                }
                            });
                            return true;
                        } else if (menuitem == R.id.menu_ruleslist_popup_clipboard) {
                            ClipboardManager clipboard = (ClipboardManager) ActivityRulesList.this.getSystemService(Context.CLIPBOARD_SERVICE);
                            ClipData clip = ClipData.newPlainText("netguard", ruletext);
                            clipboard.setPrimaryClip(clip);
                            return true;
                        }

                        return false;
                    }
                });
                popup.show();
            }
        });
    }

    // Rules changed listener is added only in onResume and not onCreate - is that good?
    // Doing it the way ActivityForwarding and ActivityLog do
    @Override
    protected void onResume() {
        super.onResume();
        DatabaseHelper.getInstance(this).addRuleChangedListener(listener);
        if (adapter != null) {
            adapter.changeCursor(DatabaseHelper.getInstance(this).getAllRules());
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        DatabaseHelper.getInstance(this).removeRuleChangedListener(listener);
    }

    @Override
    protected void onDestroy() {
        adapter = null;
        super.onDestroy();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.rulelistmenu, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        switch(item.getItemId()) {
            case R.id.menu_rules_list_add:
                launchAddRulePage(ActivityRulesList.this);
                return true;
            case R.id.copy_all_to_clipboard:
                // TODO - implement
                Log.w(TAG, "copy all to clipboard here");
                return true;
        }

        return super.onOptionsItemSelected(item);
    }

    // Launch a dialog to add an arbitrary rule
    private void launchAddRulePage(final Context context) {
        LayoutInflater inflater = LayoutInflater.from(context);
        View view = inflater.inflate(R.layout.addrule, null, false);
        final EditText etRuleText = view.findViewById(R.id.etRuleText);

        AlertDialog dialog;
        dialog = new AlertDialog.Builder(context)
                .setView(view)
                .setCancelable(true)
                .setPositiveButton(android.R.string.yes, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        String newruletext = etRuleText.getText().toString();
                        Log.w(TAG, String.format("click yes: newruletext=\"%s\"", newruletext));

                        try {
                            RulesManager.getInstance(context).queueRuleText(context, newruletext);
                        } catch (Throwable t) {
                            Log.w(TAG, String.format("New rule \"%s\" got exception %s", newruletext, t.toString()));
                        }

                        dialog.dismiss();
                    }
                })
                .setNegativeButton(android.R.string.no, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                })
                .setOnDismissListener(new DialogInterface.OnDismissListener() {
                    @Override
                    public void onDismiss(DialogInterface dialogInterface) {
                    }
                })
                .create();
        dialog.show();
    }

    private class AdapterRulesList extends CursorAdapter {
        private int colId;
        private int colRuleText;
        private int colEnacted;
        private int colEnactTime;

        public AdapterRulesList(Context context, Cursor cursor) {
            super(context, cursor, 0);

            colId = cursor.getColumnIndexOrThrow("_id");
            colRuleText = cursor.getColumnIndexOrThrow("ruletext");
            colEnacted = cursor.getColumnIndexOrThrow("enacted");
            colEnactTime = cursor.getColumnIndexOrThrow("enact_time");
        }

        @Override
        public View newView(Context context, Cursor cursor, ViewGroup parent) {
            return LayoutInflater.from(context).inflate(R.layout.rule_display, parent, false);
        }

        @Override
        public void bindView(View view, Context context, Cursor cursor) {
            long id = cursor.getLong(colId);
            String ruletext = cursor.getString(colRuleText);
            int enacted = cursor.getInt(colEnacted);
            long enact_time = cursor.getLong(colEnactTime);

            TextView tvId = view.findViewById(R.id.tvID);
            TextView tvRuleText = view.findViewById(R.id.tvRuleText);

            tvId.setText(Long.toString(id));
            if (enacted != 0) {
                tvRuleText.setText(ruletext);
            } else {
                SimpleDateFormat x = new SimpleDateFormat("LLL dd - HH:mm:ss");
                String timemessage = x.format(new Date(enact_time)).toString();
                tvRuleText.setText("### " + ruletext + " (enacts at " + timemessage + ")");
            }
        }
    }
}
