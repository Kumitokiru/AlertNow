package com.example.alertnow;

import android.content.ContentValues;
import android.content.Intent;
import android.database.Cursor;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.Spinner;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;

public class PassReset extends AppCompatActivity {

    private Spinner spinnerRole;
    private EditText etUsername;
    private EditText etContact, etPassword;
    private Button btnSave, btnBack;
    private DatabaseHelper dbHelper;

    private String selectedRole = "";
    private String username = "";
    private String contactNumber = "";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.passres);

        dbHelper = new DatabaseHelper(this);

        // Initialize views
        btnBack = findViewById(R.id.btn_back);
        spinnerRole = findViewById(R.id.spinner_role);
        etUsername = findViewById(R.id.et_username);        // NEW
        etContact = findViewById(R.id.et_contact);
        etPassword = findViewById(R.id.et_password);
        btnSave = findViewById(R.id.btn_save);

        // Setup Role Dropdown
        String[] roles = {"Resident", "Barangay", "CDRRMO", "BFP", "Health", "Hospital", "PNP"};
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this,
                android.R.layout.simple_spinner_item, roles);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerRole.setAdapter(adapter);

        // Role Selection
        spinnerRole.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                selectedRole = roles[position].toLowerCase();
                if (selectedRole.equals("barangay")) selectedRole = "official"; // DB uses "official"
                if (selectedRole.equals("health")) selectedRole = "health"; // keep as-is
                checkFields();
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                selectedRole = "";
                checkFields();
            }
        });

        // Username Input (NEW)
        etUsername.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override
            public void afterTextChanged(Editable s) {
                username = s.toString().trim();
                checkFields();
            }
        });

        // Contact Number Input
        etContact.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override
            public void afterTextChanged(Editable s) {
                contactNumber = s.toString().trim();
                checkFields();
            }
        });

        // Back Button
        btnBack.setOnClickListener(v -> {
            startActivity(new Intent(PassReset.this, StarterPage.class));
            finish();
        });

        // Save Button
        btnSave.setOnClickListener(v -> {
            String newPassword = etPassword.getText().toString().trim();

            if (newPassword.isEmpty()) {
                Toast.makeText(this, "Please enter a new password", Toast.LENGTH_SHORT).show();
                return;
            }

            boolean updated = updatePassword(selectedRole, username, contactNumber, newPassword);
            if (updated) {
                Toast.makeText(this, "Password reset successfully!", Toast.LENGTH_LONG).show();
                startActivity(new Intent(PassReset.this, StarterPage.class));
                finish();
            } else {
                Toast.makeText(this, "User not found. Please check Role, Username and Contact Number.", Toast.LENGTH_LONG).show();
            }
        });
    }

    private void checkFields() {
        boolean enabled = !selectedRole.isEmpty() &&
                (selectedRole.equals("resident") || selectedRole.equals("official") ? !username.isEmpty() : true) &&
                contactNumber.length() >= 10;
        etPassword.setEnabled(enabled);
        etPassword.setBackgroundResource(enabled ?
                R.drawable.input_background : R.drawable.input_background_disabled);
        etPassword.setTextColor(getResources().getColor(enabled ? R.color.black : R.color.gray));
    }

    private boolean updatePassword(String role, String username, String contactNo, String newPassword) {
        try {
            Cursor cursor = null;

            if (role.equals("resident")) {
                // Resident: username + role = 'resident' + contact_no
                cursor = dbHelper.getReadableDatabase().rawQuery(
                        "SELECT username FROM users WHERE username = ? AND role = ? AND contact_no = ?",
                        new String[]{username, "resident", contactNo}
                );
            } else if (role.equals("barangay")) {
                // Barangay (Official): username + role = 'official' + contact_no + position NOT NULL
                cursor = dbHelper.getReadableDatabase().rawQuery(
                        "SELECT username FROM users WHERE username = ? AND role = ? AND contact_no = ? AND position IS NOT NULL AND position != ''",
                        new String[]{username, "official", contactNo}
                );
            } else {
                // Agencies: role + contact_no (username not used)
                cursor = dbHelper.getReadableDatabase().rawQuery(
                        "SELECT username FROM users WHERE role = ? AND contact_no = ?",
                        new String[]{role, contactNo}
                );
            }

            if (cursor != null && cursor.moveToFirst()) {
                String foundUser = cursor.getString(0);
                cursor.close();

                // Update password
                ContentValues values = new ContentValues();
                values.put("password", newPassword);
                int rows = dbHelper.getWritableDatabase().update(
                        "users", values, "username = ?", new String[]{foundUser});

                return rows > 0;
            }
            if (cursor != null) cursor.close();
            return false;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}