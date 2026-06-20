package com.example.alertnow;

import android.content.ContentValues; // Import ContentValues
import android.content.Intent;
import android.os.Bundle;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import com.android.volley.RequestQueue;
import com.android.volley.toolbox.Volley;

import android.view.View;
import android.widget.AdapterView;


public class Agencyup extends AppCompatActivity {
    private DatabaseHelper dbHelper;
    private RequestQueue queue;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.agencyup);

        dbHelper = new DatabaseHelper(this);
        queue = Volley.newRequestQueue(this);

        Spinner roleSpinner = findViewById(R.id.role_spinner);
        Spinner assignedHospitalSpinner = findViewById(R.id.spinnerAssignedHospital);
        EditText municipalityEdit = findViewById(R.id.et_municipality);
        EditText contactEdit = findViewById(R.id.et_contact_no);
        EditText passwordEdit = findViewById(R.id.et_password);
        Button signupBtn = findViewById(R.id.btn_signup);

        ArrayAdapter<CharSequence> roleAdapter = ArrayAdapter.createFromResource(this,
                R.array.roles_cdrmo_pnp_bfp_health_hospital, android.R.layout.simple_spinner_item);
        roleAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        roleSpinner.setAdapter(roleAdapter);

        ArrayAdapter<CharSequence> hospitalAdapter = ArrayAdapter.createFromResource(this,
                R.array.assigned_hospitals, android.R.layout.simple_spinner_item);
        hospitalAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        assignedHospitalSpinner.setAdapter(hospitalAdapter);
        assignedHospitalSpinner.setVisibility(roleSpinner.getSelectedItem().toString().toLowerCase().equals("hospital") ? Spinner.VISIBLE : Spinner.GONE);

        roleSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                assignedHospitalSpinner.setVisibility(
                        parent.getItemAtPosition(position).toString().toLowerCase().equals("hospital") ? Spinner.VISIBLE : Spinner.GONE);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        signupBtn.setOnClickListener(v -> {
            String role = roleSpinner.getSelectedItem().toString().toLowerCase();
            String municipality = municipalityEdit.getText().toString().trim();
            String contact = contactEdit.getText().toString().trim();
            String password = passwordEdit.getText().toString().trim();
            String assignedHospital = role.equals("hospital") ? assignedHospitalSpinner.getSelectedItem().toString().toLowerCase() : null;

            String timestamp = new SimpleDateFormat("yyyyMMddHHmmss", Locale.getDefault()).format(new Date());
            String username = String.format("%s_%s_%s_%s", role, municipality, contact, timestamp);

            if (municipality.isEmpty() || contact.isEmpty() || password.isEmpty() || (role.equals("hospital") && assignedHospital == null)) {
                Toast.makeText(this, "All fields are required.", Toast.LENGTH_SHORT).show();
                return;
            }

            ContentValues values = new ContentValues();
            values.put("username", username);
            values.put("password", password);
            values.put("role", role);
            values.put("municipality", municipality);
            values.put("contact_no", contact);
            if (role.equals("hospital")) {
                values.put("assigned_hospital", assignedHospital);
            }
            values.put("synced", 0);

            boolean local_success = dbHelper.insertUser(values);

            if (local_success) {
                Toast.makeText(this, "Signup successful.", Toast.LENGTH_SHORT).show();
                startActivity(new Intent(Agencyup.this, AgencyIn.class));
                finish();
            } else {
                Toast.makeText(this, "Signup failed. Username may already exist.", Toast.LENGTH_LONG).show();
            }
        });
    }
}