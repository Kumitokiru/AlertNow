package com.example.alertnow;

import android.content.Intent;
import android.os.Bundle;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;
import org.json.JSONException;
import org.json.JSONObject;

import android.view.GestureDetector;
import android.view.MotionEvent;
import android.widget.LinearLayout;
import androidx.core.view.GestureDetectorCompat;

import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;
import org.json.JSONException;
import org.json.JSONObject;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.JsonObjectRequest;
import com.android.volley.toolbox.Volley;
import org.json.JSONException;
import org.json.JSONObject;

import androidx.core.view.GestureDetectorCompat;
import android.util.Log;
public class LoginPage extends AppCompatActivity {
    private DatabaseHelper dbHelper;
    private EditText etUsername, etPassword;
    private Button btnLogin, balikbtn;
    private RequestQueue queue;
    private SharedPreferences prefs;
    private GestureDetectorCompat gestureDetector;
    private LinearLayout profileLayout;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.loginpage);

        dbHelper = new DatabaseHelper(this);
        queue = Volley.newRequestQueue(this);
        prefs = getSharedPreferences("AlertNowPrefs", MODE_PRIVATE);

        etUsername = findViewById(R.id.etUsername);
        etPassword = findViewById(R.id.etPassword);
        btnLogin = findViewById(R.id.btnLogin);
        balikbtn = findViewById(R.id.balikbtn);
        profileLayout = findViewById(R.id.profile_layout);

        btnLogin.setOnClickListener(v -> login());
        balikbtn.setOnClickListener(v -> startActivity(new Intent(this, SignupPage.class)));

        // Inside onCreate(), after finding views:
        TextView tvForgotPassword = findViewById(R.id.tvForgotPassword);
        tvForgotPassword.setOnClickListener(v -> {
            startActivity(new Intent(LoginPage.this, PassReset.class));
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
        String username = etUsername.getText().toString().trim();
        String password = etPassword.getText().toString().trim();

        if (username.isEmpty() || password.isEmpty()) {
            Toast.makeText(this, "All fields are required.", Toast.LENGTH_SHORT).show();
            return;
        }

        String roleFromDb = dbHelper.getUserRoleByUsernamePassword(username, password);
        if (roleFromDb != null) {
            SharedPreferences.Editor editor = prefs.edit();
            editor.putString("role", roleFromDb);
            editor.putString("username", username);
            editor.apply();
            Intent intent;
            if (roleFromDb.equals("resident")) {
                intent = new Intent(LoginPage.this, ResidentPage.class);
            } else if (roleFromDb.equals("barangay")) {
                intent = new Intent(LoginPage.this, BarangayPage.class);
            } else {
                Toast.makeText(LoginPage.this, "Unknown role.", Toast.LENGTH_SHORT).show();
                return;
            }
            startActivity(intent);
            finish();
        } else {
            Toast.makeText(LoginPage.this, "Invalid credentials.", Toast.LENGTH_SHORT).show();
        }
    }

    private void showProfiles() {
        if (profileLayout == null) {
            Log.e("LoginPage", "profileLayout is null");
            return;
        }
        profileLayout.removeAllViews();
        profileLayout.setVisibility(LinearLayout.VISIBLE);
        Cursor cursor = dbHelper.getAllUsers();
        if (cursor != null && cursor.moveToFirst()) {
            do {
                String role = cursor.getString(cursor.getColumnIndexOrThrow("role"));
                String username = cursor.getString(cursor.getColumnIndexOrThrow("username"));
                String position = cursor.getString(cursor.getColumnIndexOrThrow("position"));
                String password = cursor.getString(cursor.getColumnIndexOrThrow("password"));
                Button profileButton = new Button(this);
                if (role.equalsIgnoreCase("resident")) {
                    profileButton.setText(String.format("resident %s", username));
                    profileButton.setOnClickListener(v -> autoLogin(role, username, password));
                    profileLayout.addView(profileButton);
                } else if (role.equalsIgnoreCase("official")) {
                    profileButton.setText(String.format("%s %s", position, username));
                    profileButton.setOnClickListener(v -> autoLogin(role, username, password));
                    profileLayout.addView(profileButton);
                }
            } while (cursor.moveToNext());
            cursor.close();
        } else {
            Log.e("LoginPage", "No users found or cursor is null");
        }
    }

    private void autoLogin(String role, String username, String password) {
        SharedPreferences.Editor editor = prefs.edit();
        editor.putString("username", username);
        editor.putString("role", role);
        editor.apply();
        Intent intent;
        if (role.equalsIgnoreCase("resident")) {
            intent = new Intent(this, ResidentPage.class);
            String barangay = dbHelper.getBarangayByUsername(username);
            String houseNo = dbHelper.getHouseNoByUsername(username);
            String streetNo = dbHelper.getStreetNoByUsername(username);
            editor.putString("barangay", barangay != null ? barangay : "");
            editor.putString("house_no", houseNo != null ? houseNo : "");
            editor.putString("street_no", streetNo != null ? streetNo : "");
        } else if (role.equalsIgnoreCase("official")) {
            String barangay = dbHelper.getBarangayByUsername(username);
            if (barangay == null || barangay.isEmpty()) {
                Toast.makeText(this, "Barangay not found for this user.", Toast.LENGTH_SHORT).show();
                return;
            }
            intent = new Intent(this, BarangayPage.class);
            editor.putString("barangay", barangay);
        } else {
            Toast.makeText(this, "Unknown role.", Toast.LENGTH_SHORT).show();
            return;
        }
        editor.apply();
        startActivity(intent);
        finish();
    }
}