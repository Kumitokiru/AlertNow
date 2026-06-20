package com.example.alertnow;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.ArrayAdapter;
import android.widget.TextView;
import android.widget.Toast;
import android.util.Log;
import androidx.appcompat.app.AppCompatActivity;

import android.content.SharedPreferences;

import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;
import org.json.JSONException;
import org.json.JSONObject;

import android.view.GestureDetector;
import android.view.MotionEvent;
import android.widget.LinearLayout;
import androidx.core.view.GestureDetectorCompat;

import android.database.Cursor;
import android.widget.AdapterView;


public class AgencyIn extends AppCompatActivity {
    private DatabaseHelper dbHelper;
    private EditText etMunicipality, etContactNo, etPassword;
    private Spinner spinnerRole, spinnerAssignedHospital;
    private Button btnLogin, balikbtn;
    private RequestQueue queue;
    private SharedPreferences prefs;
    private GestureDetectorCompat gestureDetector;
    private LinearLayout profileLayout;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.agencyin);

        dbHelper = new DatabaseHelper(this);
        queue = Volley.newRequestQueue(this);
        prefs = getSharedPreferences("AlertNowPrefs", MODE_PRIVATE);

        etMunicipality = findViewById(R.id.etMunicipality);
        etContactNo = findViewById(R.id.etContactNo);
        etPassword = findViewById(R.id.etPassword);
        spinnerRole = findViewById(R.id.spinnerRole);
        spinnerAssignedHospital = findViewById(R.id.spinnerAssignedHospital);
        btnLogin = findViewById(R.id.btnLogin);
        balikbtn = findViewById(R.id.balikbtn);
        profileLayout = findViewById(R.id.profile_layout);

        ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(this,
                R.array.roles_cdrmo_pnp_bfp_health_hospital, android.R.layout.simple_spinner_item);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerRole.setAdapter(adapter);

        ArrayAdapter<CharSequence> hospitalAdapter = ArrayAdapter.createFromResource(this,
                R.array.assigned_hospitals, android.R.layout.simple_spinner_item);
        hospitalAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerAssignedHospital.setAdapter(hospitalAdapter);
        spinnerAssignedHospital.setVisibility(spinnerRole.getSelectedItem().toString().toLowerCase().equals("hospital") ? Spinner.VISIBLE : Spinner.GONE);

        spinnerRole.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                spinnerAssignedHospital.setVisibility(
                        parent.getItemAtPosition(position).toString().toLowerCase().equals("hospital") ? Spinner.VISIBLE : Spinner.GONE);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        btnLogin.setOnClickListener(v -> login());
        balikbtn.setOnClickListener(v -> startActivity(new Intent(this, SignupPage.class)));

        // Inside onCreate(), after finding views:
        TextView tvForgotPassword = findViewById(R.id.tvForgotPassword);
        tvForgotPassword.setOnClickListener(v -> {
            startActivity(new Intent(AgencyIn.this, PassReset.class));
        });

        gestureDetector = new GestureDetectorCompat(this, new GestureDetector.SimpleOnGestureListener() {
            @Override
            public boolean onFling(MotionEvent e1, MotionEvent e2, float velocityX, float velocityY) {
                if (e2.getY() - e1.getY() < -150 && Math.abs(velocityY) > 200) { // Adjusted threshold
                    showProfiles();
                    return true;
                }
                return false;
            }
        });
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        gestureDetector.onTouchEvent(event);
        return super.onTouchEvent(event);
    }

    private void login() {
        String role = spinnerRole.getSelectedItem().toString().toLowerCase();
        String municipality = etMunicipality.getText().toString().trim();
        String contactNo = etContactNo.getText().toString().trim();
        String password = etPassword.getText().toString().trim();
        String assignedHospital = role.equals("hospital") ? spinnerAssignedHospital.getSelectedItem().toString() : "";

        if (municipality.isEmpty() || contactNo.isEmpty() || password.isEmpty()) {
            Toast.makeText(this, "All fields are required.", Toast.LENGTH_SHORT).show();
            return;
        }

        String roleFromDb = dbHelper.getUserRoleByMunicipalityContactNoPassword(role, municipality, contactNo, password);
        if (roleFromDb != null) {
            SharedPreferences.Editor editor = prefs.edit();
            editor.putString("role", roleFromDb);
            editor.putString("municipality", municipality);
            editor.putString("contact_no", contactNo);
            if (role.equals("hospital")) {
                editor.putString("assigned_hospital", assignedHospital);
            }
            editor.apply();
            Intent intent;
            if (roleFromDb.equals("cdrrmo")) {
                intent = new Intent(AgencyIn.this, CDRRMOPage.class);
            } else if (roleFromDb.equals("pnp")) {
                intent = new Intent(AgencyIn.this, PNPPage.class);
            } else if (roleFromDb.equals("bfp")) {
                intent = new Intent(AgencyIn.this, BFPPage.class);
            } else if (roleFromDb.equals("health")) {
                intent = new Intent(AgencyIn.this, CityHealthPage.class);
            } else if (roleFromDb.equals("hospital")) {
                intent = new Intent(AgencyIn.this, HospitalsPage.class);
            } else {
                Toast.makeText(AgencyIn.this, "Unknown role.", Toast.LENGTH_SHORT).show();
                return;
            }
            startActivity(intent);
            finish();
        } else {
            Toast.makeText(AgencyIn.this, "Invalid credentials.", Toast.LENGTH_SHORT).show();
        }
    }

    private void showProfiles() {
        if (profileLayout == null) {
            Log.e("AgencyIn", "profileLayout is null");
            return;
        }
        profileLayout.removeAllViews();
        profileLayout.setVisibility(LinearLayout.VISIBLE);
        Cursor cursor = dbHelper.getUsersByRoles("cdrrmo", "pnp", "bfp", "health", "hospital");
        if (cursor != null && cursor.moveToFirst()) {
            do {
                String role = cursor.getString(cursor.getColumnIndexOrThrow("role"));
                String municipality = cursor.getString(cursor.getColumnIndexOrThrow("municipality"));
                String contactNo = cursor.getString(cursor.getColumnIndexOrThrow("contact_no"));
                String password = cursor.getString(cursor.getColumnIndexOrThrow("password"));
                String assignedHospital = cursor.getString(cursor.getColumnIndexOrThrow("assigned_hospital"));
                Button profileButton = new Button(this);
                if (role.equals("hospital")) {
                    profileButton.setText(String.format("%s %s", assignedHospital != null ? assignedHospital : "Unknown Hospital", municipality));
                } else {
                    profileButton.setText(String.format("%s %s", role.toUpperCase(), municipality));
                }
                profileButton.setOnClickListener(v -> autoLogin(role, municipality, contactNo, password, assignedHospital));
                profileLayout.addView(profileButton);
            } while (cursor.moveToNext());
            cursor.close();
        } else {
            Log.e("AgencyIn", "No users found or cursor is null");
            Button noUsersButton = new Button(this);
            noUsersButton.setText("No CDRRMO/PNP/BFP/City Health/Hospital users found.");
            profileLayout.addView(noUsersButton);
        }
    }

    private void autoLogin(String role, String municipality, String contactNo, String password, String assignedHospital) {
        String roleFromDb = dbHelper.getUserRoleByMunicipalityContactNoPassword(role, municipality, contactNo, password);
        if (roleFromDb != null) {
            SharedPreferences.Editor editor = prefs.edit();
            editor.putString("role", roleFromDb);
            editor.putString("municipality", municipality);
            editor.putString("contact_no", contactNo);
            if (role.equals("hospital")) {
                editor.putString("assigned_hospital", assignedHospital);
            }
            editor.apply();
            Intent intent;
            if (roleFromDb.equals("cdrrmo")) {
                intent = new Intent(this, CDRRMOPage.class);
            } else if (roleFromDb.equals("pnp")) {
                intent = new Intent(this, PNPPage.class);
            } else if (roleFromDb.equals("bfp")) {
                intent = new Intent(this, BFPPage.class);
            } else if (roleFromDb.equals("health")) {
                intent = new Intent(this, CityHealthPage.class);
            } else if (roleFromDb.equals("hospital")) {
                intent = new Intent(this, HospitalsPage.class);
            } else {
                Toast.makeText(this, "Unknown role.", Toast.LENGTH_SHORT).show();
                return;
            }
            startActivity(intent);
            finish();
        } else {
            Toast.makeText(this, "Invalid credentials.", Toast.LENGTH_SHORT).show();
        }
    }
}