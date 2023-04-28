package eu.faircode.netguard;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import androidx.appcompat.app.AppCompatActivity;

// Activity to add or edit rules in a multi-line edit window

public class ActivityRulesEntry extends AppCompatActivity {
    private static final String TAG = "NetGuard.ActRulesEntry";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        Button submit;

        Util.setTheme(this);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.rules_entry);

        getSupportActionBar().setTitle(R.string.rules_entry);
        getSupportActionBar().setDisplayHomeAsUpEnabled(true);

        submit = findViewById(R.id.submit_button);
        submit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                EditText et;

                et = findViewById(R.id.etAddMultipleRules);
                submitText(et.getText().toString());
            }
        });
    }

    private void submitText(String text) {
        RulesManager rm = RulesManager.getInstance(this);
        String[] lines = text.split("\n");

        for (int i = 0; i < lines.length; i++) {
            lines[i] = lines[i].trim();
            rm.queueRuleText(this, lines[i]);
        }

        super.finish();
    }

}
