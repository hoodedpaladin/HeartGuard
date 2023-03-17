package eu.faircode.netguard;

import android.content.Context;
import android.database.Cursor;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CursorAdapter;
import android.widget.ListView;
import android.widget.TextView;

import androidx.annotation.NonNull;
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
        adapter = new AdapterRulesList(this, DatabaseHelper.getInstance(this).getAllRulesForAdapter());
        lvRulesList.setAdapter(adapter);
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
        inflater.inflate(R.menu.forwarding, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
        switch(item.getItemId()) {
            case R.id.menu_add:
                Log.w(TAG, "add item, cool");
                return true;
        }

        return super.onOptionsItemSelected(item);
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
