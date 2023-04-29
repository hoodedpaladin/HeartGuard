package eu.faircode.netguard;

import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

// Activity to add or edit rules in a multi-line edit window

public class ActivityRulesEntry extends AppCompatActivity {
    private static final String TAG = "NetGuard.ActRulesEntry";
    public final static String SPECIFY_MODE = "mode";
    public final static int MODE_ADD_RULES = 1;
    public final static int MODE_EDIT_RULES = 2;
    public final static int MODE_SUBMIT_CHANGES = 3;

    private int m_mode = MODE_ADD_RULES;
    List<String> m_solid_rules = new LinkedList<>();
    List<String> m_pending_additions = new LinkedList<>();
    List<String> m_pending_deletions = new LinkedList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Bundle extras = getIntent().getExtras();

        if ((extras != null) && (extras.containsKey(SPECIFY_MODE))) {
            m_mode = extras.getInt(SPECIFY_MODE, MODE_ADD_RULES);
        }

        Util.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.rules_entry);

        getSupportActionBar().setTitle(R.string.rules_entry);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        if (m_mode == MODE_ADD_RULES) {
        } else if (m_mode == MODE_EDIT_RULES) {
            // Set up the window for Raw Edit mode
            TextView header = findViewById(R.id.tvRulesEntryHeader);
            header.setText(R.string.edit_rules);
            getCurrentRuleset();
            buildTextBoxFromCurrentRuleset();
        } else if (m_mode == MODE_SUBMIT_CHANGES) {
            // Set up the window for Submit Changes mode
            TextView header = findViewById(R.id.tvRulesEntryHeader);
            header.setText(R.string.submit_these_changes);
            if (extras != null) {
                String text = extras.getString("edittext");
                EditText et = findViewById(R.id.etAddMultipleRules);
                et.setText(text);
            }
        } else {
            Log.e(TAG, "Mode " + m_mode + " is invalid");
            super.finish();
        }

        Button submit = findViewById(R.id.submit_button);
        submit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                EditText et;

                et = findViewById(R.id.etAddMultipleRules);
                String text = et.getText().toString();
                if (m_mode == MODE_ADD_RULES) {
                    submitText(text);
                } else if (m_mode == MODE_EDIT_RULES) {
                    submitRawEdit(text);
                    ActivityRulesEntry.super.finish();
                } else if (m_mode == MODE_SUBMIT_CHANGES) {
                    submitText(text);
                }
            }
        });
    }

    // The submit button has been pressed, so submit all lines
    private void submitText(String text) {
        RulesManager rm = RulesManager.getInstance(this);
        String[] lines = text.split("\n");

        for (String line : lines) {
            line = line.trim();
            if (line.length() == 0) {
                continue;
            }
            rm.queueRuleText(this, line);
        }

        super.finish();
    }

    // Check the current rules for currently enacted rules and pending additions and deletions
    // If there is a pending deletion, the corresponding enacted rule is not "solid"
    private void getCurrentRuleset() {
        DatabaseHelper dh = DatabaseHelper.getInstance(this);
        Cursor cursor = dh.getAllRulesSorted();

        int col_ruletext = cursor.getColumnIndexOrThrow("ruletext");
        int col_enacted = cursor.getColumnIndexOrThrow("enacted");

        m_solid_rules = new LinkedList<>();
        m_pending_additions = new LinkedList<>();
        m_pending_deletions = new LinkedList<>();
        while(cursor.moveToNext()) {
            boolean enacted = cursor.getInt(col_enacted) > 0;
            String ruletext = cursor.getString(col_ruletext);

            if (ruletext.matches("- .*")) {
                String delete_rule = ruletext.substring(2);

                if (delete_rule.startsWith("delay") || delete_rule.startsWith("partner")) {
                    // Ignore delay additions and deletions
                    continue;
                }
                for (int i = 0; i < m_solid_rules.size(); i++) {
                    if (m_solid_rules.get(i).equals(delete_rule)) {
                        m_solid_rules.remove(i);
                        i -= 1;
                    }
                }
                m_pending_deletions.add(delete_rule);
            } else {
                if (ruletext.startsWith("delay") || ruletext.startsWith("partner")) {
                    // Ignore delay additions and deletions
                    continue;
                }
                if (enacted) {
                    m_solid_rules.add(ruletext);
                } else {
                    m_pending_additions.add(ruletext);
                }
            }
        }
    }

    // Build the EditText contents based on the current ruleset
    private void buildTextBoxFromCurrentRuleset() {
        List<String> ruleStrings = new LinkedList<>();

        for (String text : m_solid_rules) {
            ruleStrings.add(text);
        }
        for (String text : m_pending_additions) {
            ruleStrings.add(text);
        }
        for (String text : m_pending_deletions) {
            ruleStrings.add("###removing###" + text);
        }

        String message = stringListToNewline(ruleStrings);

        EditText et = findViewById(R.id.etAddMultipleRules);
        et.setText(message);
    }

    // Util to coallesce a list of strings into a newline-separated string
    public static String stringListToNewline(List<String> strings) {
        String message = "";
        int count = 0;

        for (String string : strings) {
            if (count > 0) {
                message += "\n";
            }
            count += 1;
            message += string;
        }

        return message;
    }

    // Beginning editing text box = solid rules + pending additions
    // When text box is done:
    // Every solid rule that isn't present has been deleted
    // Every addition that isn't present has been abandoned
    // Every line that isn't one of those is either a new addition OR a pending deletion that is abandoned
    // Raw abandon and deletion commands will be ignored
    // Delay commands will be ignored
    private void submitRawEdit(String text) {
        Set<String> editBuffer = new HashSet<>();

        String[] lines = text.split("\n");

        for (String line : lines) {
            line = line.trim();
            if (line.length() == 0) {
                continue;
            }
            if (line.startsWith("###removing###")) {
                continue;
            }
            if (line.startsWith("-")) {
                return;
            }
            if (line.startsWith("abandon")) {
                return;
            }
            if (line.startsWith("delay")) {
                continue;
            }
            editBuffer.add(line);
        }

        // We should take action on any items that we put into these lists
        List<String> abandon_deletions = new LinkedList<>();
        List<String> new_additions = new LinkedList<>();
        List<String> new_deletions = new LinkedList<>();
        List<String> abandon_additions = new LinkedList<>();

        // Check for all the changes
        for (String rule : editBuffer) {
            if (m_solid_rules.remove(rule)) {
                // This is a normal rule that is still present; completely normal
                continue;
            }
            if (m_pending_additions.remove(rule)) {
                // This is a pending addition that is still present; no change
                continue;
            }
            if (m_pending_deletions.remove(rule)) {
                // This is a pending deletion that is present now - abandon the deletion
                abandon_deletions.add(rule);
                continue;
            }
            // This is a completely new rule
            new_additions.add(rule);
        }

        // The leftover solid rules and pending additions are gone now
        for (String rule : m_solid_rules) {
            new_deletions.add(rule);
        }
        for (String rule : m_pending_additions) {
            abandon_additions.add(rule);
        }

        List<String> rulesToQueue = new LinkedList<>();

        for (String rule : abandon_deletions) {
            rulesToQueue.add("abandon - " + rule);
        }
        for (String rule : abandon_additions) {
            rulesToQueue.add("abandon " + rule);
        }
        for (String rule : new_deletions) {
            rulesToQueue.add("- " + rule);
        }
        for (String rule : new_additions) {
            rulesToQueue.add(rule);
        }
        if (rulesToQueue.size() == 0) {
            return;
        }

        // Put these new changes into a new window for the user to confirm
        startActivityToConfirmRules(this, rulesToQueue);
    }

    // Pop up a new window with a list of rules for the user to confirm
    public static void startActivityToConfirmRules(Context context, List<String> newrules) {
        Intent i = new Intent(context, ActivityRulesEntry.class);
        String message = stringListToNewline(newrules);
        i.putExtra("edittext", message);
        i.putExtra(SPECIFY_MODE, MODE_SUBMIT_CHANGES);
        context.startActivity(i);
    }
}
