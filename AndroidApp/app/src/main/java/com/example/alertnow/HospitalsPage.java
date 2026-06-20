package com.example.alertnow;

import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.media.MediaPlayer;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import io.socket.client.IO;
import io.socket.client.Socket;

import org.json.JSONException;
import org.json.JSONObject;
import android.widget.Toast;

import android.content.SharedPreferences;


import androidx.appcompat.app.AlertDialog;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.util.Base64;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;


public class HospitalsPage extends AppCompatActivity {
    private Socket socket;
    private Button logoutBtn;
    private SharedPreferences prefs;
    private List<JSONObject> alertsList;
    private LinearLayout alertsContainer;
    private MediaPlayer mediaPlayer;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.hospitalpage);

        prefs = getSharedPreferences("AlertNowPrefs", MODE_PRIVATE);
        String savedUsername = prefs.getString("username", null);
        String savedMunicipality = prefs.getString("assigned_municipality", null);
        String savedRole = prefs.getString("role", null);
        if (savedUsername == null || savedMunicipality == null || savedMunicipality.isEmpty() || savedRole == null || !savedRole.equals("hospital")) {
            Log.w("HospitalsPage", "Invalid credentials, redirecting to LoginPage");
            Toast.makeText(this, "Please log in", Toast.LENGTH_SHORT).show();
            startActivity(new Intent(this, LoginPage.class));
            finish();
            return;
        }

        TextView barangayLabel = new TextView(this);
        barangayLabel.setText("Hospital " + savedMunicipality);
        barangayLabel.setTextColor(Color.WHITE);
        barangayLabel.setTextSize(16);
        barangayLabel.setPadding(16, 150, 16, 10);
        ((ViewGroup) findViewById(android.R.id.content)).addView(barangayLabel, new ViewGroup.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        // === REMOVE FROM XML → DEFINE IN JAVA ===
        alertsList = new ArrayList<>();
        alertsContainer = new LinearLayout(this);
        alertsContainer.setOrientation(LinearLayout.VERTICAL);
        alertsContainer.setPadding(16, 180, 16, 16); // Starts below nav_bar

        ScrollView scrollView = new ScrollView(this);
        scrollView.addView(alertsContainer);

        // Add scrollView to root (behind nav_bar)
        RelativeLayout rootLayout = findViewById(R.id.hospitalPageLayout);
        rootLayout.addView(scrollView, new RelativeLayout.LayoutParams(
                RelativeLayout.LayoutParams.MATCH_PARENT,
                RelativeLayout.LayoutParams.MATCH_PARENT
        ));

        // Ensure scrollView is BELOW nav_bar but covers full screen
        RelativeLayout.LayoutParams params = (RelativeLayout.LayoutParams) scrollView.getLayoutParams();
        params.addRule(RelativeLayout.BELOW, R.id.nav_bar);
        scrollView.setLayoutParams(params);

        // Enable clipping so content scrolls under nav_bar
        scrollView.setClipToPadding(false);
        scrollView.setPadding(0, 100, 0, 0); // Extra top padding for smooth scroll

        CoordinatesUtil.loadCoordinates(this);

        initializeSocket();

        logoutBtn.setOnClickListener(v -> {
            socket.disconnect();
            startActivity(new Intent(this, LoginPage.class));
            finish();
        });

        if (!isNetworkAvailable()) {
            Toast.makeText(this, "Offline, cannot receive new alerts", Toast.LENGTH_LONG).show();
        }
    }

    private void initializeSocket() {
        try {
            socket = IO.socket("https://alertnow-wi0n.onrender.com");
            socket.on(Socket.EVENT_CONNECT, args -> {
                Log.d("HospitalsPage", "Socket connected");
                try {
                    socket.emit("register_role", new JSONObject()
                            .put("role", "hospital")
                            .put("municipality", prefs.getString("assigned_municipality", "").toLowerCase()));
                } catch (org.json.JSONException e) {
                    Log.e("HospitalsPage", "JSON error in socket connect: " + e.getMessage());
                }
            }).on("hospital_alert", args -> {
                Log.d("HospitalsPage", "Received hospital_alert: " + args[0].toString());
                try {
                    JSONObject alert = (JSONObject) args[0];
                    runOnUiThread(() -> displayAlert(alert));
                } catch (Exception e) {
                    Log.e("HospitalsPage", "Error processing hospital_alert: " + e.getMessage());
                    Toast.makeText(this, "Error processing alert", Toast.LENGTH_SHORT).show();
                }
            }).on(Socket.EVENT_DISCONNECT, args -> {
                Log.d("HospitalsPage", "Socket disconnected, attempting to reconnect");
                socket.connect();
            }).on(Socket.EVENT_CONNECT_ERROR, args -> Log.e("HospitalsPage", "Connection error: " + args[0]));
            socket.connect();
        } catch (Exception e) {
            Log.e("HospitalsPage", "Socket initialization failed: " + e.getMessage());
            Toast.makeText(this, "Socket initialization failed", Toast.LENGTH_SHORT).show();
        }
    }

    private void displayAlert(JSONObject alert) {
        alertsList.add(alert);
        try {
            String alertId = alert.getString("alert_id");
            String barangay = alert.getString("barangay");
            String emergencyType = alert.optString("emergency_type", "Health Emergency");
            String residentBarangay = alert.optString("resident_barangay", barangay);
            String timestamp = alert.getString("timestamp");
            String healthType = alert.optString("health_type", "N/A");
            String healthCause = alert.optString("health_cause", "N/A");
            String patientAge = alert.optString("patient_age", "N/A");
            String patientGender = alert.optString("patient_gender", "N/A");
            String hospitalName = alert.getString("hospital_name");
            double lat = alert.getDouble("lat");
            double lon = alert.getDouble("lon");

            LinearLayout alertLayout = new LinearLayout(this);
            alertLayout.setOrientation(LinearLayout.VERTICAL);
            alertLayout.setPadding(10, 10, 10, 10);
            alertLayout.setBackgroundColor(Color.parseColor("#1F3458"));

            TextView statusTextView = new TextView(this);
            statusTextView.setText("RESPONDED");
            statusTextView.setTextColor(Color.WHITE);
            statusTextView.setTextSize(16);
            statusTextView.setTypeface(null, Typeface.BOLD);

            TextView alertText = new TextView(this);
            alertText.setText("Health Emergency and On The Way To " + hospitalName + "\nResident From " + residentBarangay);
            alertText.setTextColor(Color.WHITE);
            alertText.setTextSize(16);

            TextView timeTextView = new TextView(this);
            timeTextView.setText("Time: " + timestamp);
            timeTextView.setTextColor(Color.WHITE);
            timeTextView.setTextSize(16);

            TextView healthTypeTextView = new TextView(this);
            healthTypeTextView.setText("Health Type: " + healthType);
            healthTypeTextView.setTextColor(Color.WHITE);
            healthTypeTextView.setTextSize(16);

            TextView healthCauseTextView = new TextView(this);
            healthCauseTextView.setText("Health Cause: " + healthCause);
            healthCauseTextView.setTextColor(Color.WHITE);
            healthCauseTextView.setTextSize(16);

            TextView patientAgeTextView = new TextView(this);
            patientAgeTextView.setText("Patient Age: " + patientAge);
            patientAgeTextView.setTextColor(Color.WHITE);
            patientAgeTextView.setTextSize(16);

            TextView patientGenderTextView = new TextView(this);
            patientGenderTextView.setText("Patient Gender: " + patientGender);
            patientGenderTextView.setTextColor(Color.WHITE);
            patientGenderTextView.setTextSize(16);

            ImageView alertImageView = new ImageView(this);
            alertImageView.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 200));
            alertImageView.setVisibility(View.GONE);
            if (alert.has("image")) {
                String imageBase64 = alert.getString("image");
                Util.loadBase64IntoView(imageBase64, alertImageView);
                alertImageView.setVisibility(View.VISIBLE);
                alertImageView.setOnClickListener(v -> {
                    byte[] decodedString = Base64.decode(imageBase64, Base64.DEFAULT);
                    Bitmap decodedByte = BitmapFactory.decodeByteArray(decodedString, 0, decodedString.length);
                    AlertDialog.Builder builder = new AlertDialog.Builder(HospitalsPage.this);
                    ImageView dialogImage = new ImageView(HospitalsPage.this);
                    dialogImage.setImageBitmap(decodedByte);
                    dialogImage.setAdjustViewBounds(true);
                    builder.setView(dialogImage);
                    AlertDialog dialog = builder.create();
                    dialog.show();
                    if (dialog.getWindow() != null) {
                        dialog.getWindow().setLayout(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                    }
                });
            }

            alertLayout.addView(statusTextView);
            alertLayout.addView(alertText);
            alertLayout.addView(timeTextView);
            alertLayout.addView(healthTypeTextView);
            alertLayout.addView(healthCauseTextView);
            alertLayout.addView(patientAgeTextView);
            alertLayout.addView(patientGenderTextView);
            alertLayout.addView(alertImageView);

            alertsContainer.addView(alertLayout, 0);
        } catch (Exception e) {
            Log.e("HospitalsPage", "Error displaying alert: " + e.getMessage());
            Toast.makeText(this, "Error displaying alert", Toast.LENGTH_SHORT).show();
        }
    }

    private boolean isNetworkAvailable() {
        ConnectivityManager connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
        return activeNetworkInfo != null && activeNetworkInfo.isConnected();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (socket != null) {
            socket.disconnect();
        }
        if (mediaPlayer != null) {
            mediaPlayer.release();
            mediaPlayer = null;
        }

    }
}