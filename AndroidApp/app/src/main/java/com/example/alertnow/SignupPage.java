package com.example.alertnow;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import com.google.android.gms.location.FusedLocationProviderClient;
import com.google.android.gms.location.LocationServices;
import android.location.Address;
import android.location.Geocoder;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import android.content.ContentValues;


public class SignupPage extends AppCompatActivity {
    private static final int LOCATION_PERM_REQ = 1003;
    private FusedLocationProviderClient fusedLocationClient;
    private EditText etUsername, etFirstName, etMiddleName, etLastName, etAge, etContactNo, etPassword;
    private EditText etHouseNo, etStreetNo, etCity, etProvince, etBarangay;
    private Spinner roleSpinner, positionSpinner;
    private Button btnQuickScan, btnBack, btnNext, btnSignup;
    private DatabaseHelper dbHelper;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.signuppage);

        fusedLocationClient = LocationServices.getFusedLocationProviderClient(this);
        dbHelper = new DatabaseHelper(this);

        // Initialize UI elements
        etUsername = findViewById(R.id.etUsername);
        etFirstName = findViewById(R.id.etFirstName);
        etMiddleName = findViewById(R.id.etMiddleName);
        etLastName = findViewById(R.id.etLastName);
        etAge = findViewById(R.id.etAge);
        etContactNo = findViewById(R.id.etContactNo);
        etPassword = findViewById(R.id.etPassword);
        roleSpinner = findViewById(R.id.spinnerRole);
        positionSpinner = findViewById(R.id.spinnerPosition);
        etHouseNo = findViewById(R.id.etHouseNo);
        etStreetNo = findViewById(R.id.etStreetNo);
        etBarangay = findViewById(R.id.etBarangay);
        etCity = findViewById(R.id.etCity);
        etProvince = findViewById(R.id.etProvince);
        btnQuickScan = findViewById(R.id.button_quick_map_scan);
        btnBack = findViewById(R.id.button_back);
        btnNext = findViewById(R.id.button_next);
        btnSignup = findViewById(R.id.button_signup);

        // Set up spinners
        ArrayAdapter<CharSequence> roleAdapter = ArrayAdapter.createFromResource(this,
                R.array.roles, android.R.layout.simple_spinner_item);
        roleAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        roleSpinner.setAdapter(roleAdapter);

        ArrayAdapter<CharSequence> positionAdapter = ArrayAdapter.createFromResource(this,
                R.array.official_positions, android.R.layout.simple_spinner_item);
        positionAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        positionSpinner.setAdapter(positionAdapter);
        positionSpinner.setVisibility(View.GONE);

        roleSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                positionSpinner.setVisibility(
                        parent.getItemAtPosition(position).toString().equals("Official") ? View.VISIBLE : View.GONE);
            }

            @Override
            public void onNothingSelected(AdapterView<?> parent) {}
        });

        // Set up button listeners
        btnQuickScan.setOnClickListener(v -> scanLocation());
        btnBack.setOnClickListener(v -> onBackPressed());
        btnNext.setOnClickListener(v -> {
            findViewById(R.id.personal_info_layout).setVisibility(View.GONE);
            findViewById(R.id.address_layout).setVisibility(View.VISIBLE);
            btnBack.setVisibility(View.VISIBLE);
            btnSignup.setVisibility(View.VISIBLE);
            btnNext.setVisibility(View.GONE);
        });
        btnSignup.setOnClickListener(v -> signup());
    }

    private void signup() {
        String username = etUsername.getText().toString().trim();
        String first_name = etFirstName.getText().toString().trim();
        String middle_name = etMiddleName.getText().toString().trim();
        String last_name = etLastName.getText().toString().trim();
        String age = etAge.getText().toString().trim();
        String contact_no = etContactNo.getText().toString().trim();
        String password = etPassword.getText().toString().trim();
        String role = roleSpinner.getSelectedItem().toString().toLowerCase().equals("resident") ? "resident" : "official";
        String position = role.equals("official") ? positionSpinner.getSelectedItem().toString() : null;
        String house_no = etHouseNo.getText().toString().trim(); // Optional
        String street_no = etStreetNo.getText().toString().trim(); // Optional
        String barangay = etBarangay.getText().toString().trim();
        String city = etCity.getText().toString().trim();
        String province = etProvince.getText().toString().trim();

        if (username.isEmpty() || first_name.isEmpty() || last_name.isEmpty() || contact_no.isEmpty() || password.isEmpty()
                || barangay.isEmpty() || city.isEmpty() || province.isEmpty()) {
            Toast.makeText(this, "Required fields cannot be empty.", Toast.LENGTH_SHORT).show();
            return;
        }

        // Create ContentValues object to store user data
        ContentValues values = new ContentValues();
        values.put("username", username);
        values.put("password", password);
        values.put("role", role);
        values.put("first_name", first_name);
        values.put("middle_name", middle_name);
        values.put("last_name", last_name);
        if (!age.isEmpty()) {
            values.put("age", Integer.parseInt(age));
        } else {
            values.putNull("age");
        }
        values.put("contact_no", contact_no);
        values.put("house_no", house_no.isEmpty() ? null : house_no); // Optional
        values.put("street_no", street_no.isEmpty() ? null : street_no); // Optional
        values.put("barangay", barangay);
        values.put("municipality", city);
        values.put("province", province);
        if (role.equals("official")) {
            values.put("position", position);
        }
        values.put("synced", 0);

        boolean local_success = dbHelper.insertUser(values);

        if (local_success) {
            Toast.makeText(this, "Signup successful.", Toast.LENGTH_SHORT).show();
            startActivity(new Intent(this, LoginPage.class));
            finish();
        } else {
            Toast.makeText(this, "Signup failed. Username may already exist.", Toast.LENGTH_SHORT).show();
        }
    }

    private void scanLocation() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, LOCATION_PERM_REQ);
            return;
        }

        fusedLocationClient.getLastLocation()
                .addOnSuccessListener(this, location -> {
                    if (location != null) {
                        double lat = location.getLatitude();
                        double lon = location.getLongitude();
                        Geocoder geocoder = new Geocoder(this, Locale.getDefault());
                        try {
                            List<Address> addresses = geocoder.getFromLocation(lat, lon, 1);
                            if (!addresses.isEmpty()) {
                                Address address = addresses.get(0);
                                etBarangay.setText(address.getSubLocality() != null ? address.getSubLocality() : "");
                                etCity.setText(address.getLocality() != null ? address.getLocality() : "");
                                etProvince.setText(address.getAdminArea() != null ? address.getAdminArea() : "");
                            } else {
                                Toast.makeText(this, "No address found.", Toast.LENGTH_SHORT).show();
                            }
                        } catch (IOException e) {
                            Toast.makeText(this, "Geocoding failed: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                        }
                    } else {
                        Toast.makeText(this, "Location unavailable, enable GPS.", Toast.LENGTH_SHORT).show();
                    }
                });
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == LOCATION_PERM_REQ && grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            scanLocation();
        } else {
            Toast.makeText(this, "Location permission required.", Toast.LENGTH_SHORT).show();
        }
    }
}