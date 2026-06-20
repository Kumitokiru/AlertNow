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


import android.widget.CheckBox;


public class BarangayPage extends AppCompatActivity {
    private Socket socket;
    private Button logoutBtn;
    private MediaPlayer mediaPlayer;
    private JSONObject currentAlert;
    private DatabaseHelper dbHelper;
    private SharedPreferences prefs;
    private List<JSONObject> alertsList;
    private LinearLayout alertsContainer;
    private CheckBox acceptCheckBox, declineCheckBox;
    private LinearLayout responseButtonsLayout;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.officialpage);

        prefs = getSharedPreferences("AlertNowPrefs", MODE_PRIVATE);
        String savedUsername = prefs.getString("username", null);
        String savedBarangay = prefs.getString("barangay", null);
        String savedRole = prefs.getString("role", null);
        if (savedUsername == null || savedBarangay == null || savedBarangay.isEmpty() || savedRole == null || !savedRole.equals("official")) {
            Log.w("BarangayPage", "Invalid credentials, redirecting to LoginPage");
            Toast.makeText(this, "Please log in", Toast.LENGTH_SHORT).show();
            startActivity(new Intent(this, LoginPage.class));
            finish();
            return;
        }

        try {
            dbHelper = new DatabaseHelper(this);
        } catch (Exception e) {
            Log.e("BarangayPage", "Error initializing DatabaseHelper: " + e.getMessage(), e);
            Toast.makeText(this, "Database initialization error", Toast.LENGTH_LONG).show();
            finish();
            return;
        }

        logoutBtn = findViewById(R.id.layas);

        TextView barangayLabel = new TextView(this);
        barangayLabel.setText("Barangay " + savedBarangay);
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
        RelativeLayout rootLayout = findViewById(R.id.barangayPageLayout);
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
                Log.d("BarangayPage", "Socket connected");
                try {
                    socket.emit("register_role", new JSONObject()
                            .put("role", "barangay")
                            .put("barangay", prefs.getString("barangay", "").toLowerCase()));
                } catch (org.json.JSONException e) {
                    Log.e("BarangayPage", "JSON error in socket connect: " + e.getMessage());
                }
            }).on("new_alert", args -> {
                Log.d("BarangayPage", "Received new_alert: " + args[0].toString());
                try {
                    JSONObject alert = (JSONObject) args[0];
                    runOnUiThread(() -> displayAlert(alert));
                } catch (Exception e) {
                    Log.e("BarangayPage", "Error processing new_alert: " + e.getMessage());
                }
            }).on("barangay_response", args -> {
                Log.d("BarangayPage", "Received barangay_response: " + args[0].toString());
            }).on(Socket.EVENT_DISCONNECT, args -> {
                Log.d("BarangayPage", "Socket disconnected, attempting to reconnect");
                socket.connect();
            }).on(Socket.EVENT_CONNECT_ERROR, args -> Log.e("BarangayPage", "Connection error: " + args[0]));
            socket.connect();
        } catch (Exception e) {
            Log.e("BarangayPage", "Socket initialization failed: " + e.getMessage());
        }
    }

    private void displayAlert(JSONObject alert) {
        alertsList.add(alert);
        try {
            String alertId = alert.getString("alert_id");
            String houseNo = alert.optString("house_no", "N/A");
            String streetNo = alert.optString("street_no", "N/A");
            String alertBarangay = alert.getString("barangay");
            String type = alert.optString("emergency_type", "N/A");
            double lat = alert.getDouble("lat");
            double lon = alert.getDouble("lon");

            LinearLayout alertLayout = new LinearLayout(this);
            alertLayout.setOrientation(LinearLayout.VERTICAL);
            alertLayout.setPadding(10, 10, 10, 10);
            alertLayout.setBackgroundColor(Color.parseColor("#1F3458"));

            TextView statusTextView = new TextView(this);
            statusTextView.setText("PENDING ALERT");
            statusTextView.setTextColor(Color.WHITE);
            statusTextView.setTextSize(16);
            statusTextView.setTypeface(null, Typeface.BOLD);

            TextView alertText = new TextView(this);
            alertText.setText("RECEIVED ALERTS\nEmergency at " + alertBarangay + " Resident from " + alert.optString("resident_barangay", alertBarangay));
            alertText.setTextColor(Color.WHITE);
            alertText.setTextSize(16);

            TextView typeTextView = new TextView(this);
            typeTextView.setText("Type: " + type);
            typeTextView.setTextColor(Color.WHITE);
            typeTextView.setTextSize(16);
            typeTextView.setTypeface(null, Typeface.BOLD);
            typeTextView.setVisibility(View.GONE);

            TextView timeTextView = new TextView(this);
            timeTextView.setText("Time: " + new SimpleDateFormat("hh:mm a").format(new Date()));
            timeTextView.setTextColor(Color.WHITE);
            timeTextView.setTextSize(16);

            ImageView alertImageView = new ImageView(this);
            alertImageView.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 400));
            alertImageView.setVisibility(View.GONE);

            if (alert.has("image")) {
                String imageBase64 = alert.getString("image");
                Util.loadBase64IntoView(imageBase64, alertImageView);
                alertImageView.setVisibility(View.VISIBLE);
                alertImageView.setOnClickListener(v -> {
                    byte[] decodedString = Base64.decode(imageBase64, Base64.DEFAULT);
                    Bitmap decodedByte = BitmapFactory.decodeByteArray(decodedString, 0, decodedString.length);
                    AlertDialog.Builder builder = new AlertDialog.Builder(BarangayPage.this);
                    ImageView dialogImage = new ImageView(BarangayPage.this);
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

            acceptCheckBox = new CheckBox(this);
            acceptCheckBox.setText("Accept");
            acceptCheckBox.setTextSize(20);
            acceptCheckBox.setTextColor(Color.WHITE);

            declineCheckBox = new CheckBox(this);
            declineCheckBox.setText("Decline");
            declineCheckBox.setTextSize(20);
            declineCheckBox.setTextColor(Color.WHITE);

            responseButtonsLayout = new LinearLayout(this);
            responseButtonsLayout.setOrientation(LinearLayout.VERTICAL);
            responseButtonsLayout.setPadding(0, 0, 0, 20);
            responseButtonsLayout.setGravity(Gravity.CENTER);
            responseButtonsLayout.setVisibility(View.GONE);

            if (mediaPlayer == null) {
                mediaPlayer = MediaPlayer.create(this, R.raw.alert);
                mediaPlayer.setLooping(true);
                mediaPlayer.start();
            }

            LinearLayout pnpEmergencyTypeLayout = new LinearLayout(this);
            pnpEmergencyTypeLayout.setOrientation(LinearLayout.VERTICAL);
            pnpEmergencyTypeLayout.setPadding(0, 0, 0, 20);
            pnpEmergencyTypeLayout.setGravity(Gravity.CENTER);
            pnpEmergencyTypeLayout.setVisibility(View.GONE);

            String[] pnpEmergencyTypes = {"Road Accident", "Fire Incident", "Crime Incident"};
            List<Button> pnpButtons = new ArrayList<>();
            for (String emergencyType : pnpEmergencyTypes) {
                Button pnpButton = new Button(this);
                pnpButton.setText(emergencyType);
                pnpButton.setBackgroundResource(R.drawable.button_background);
                pnpButton.setPadding(0, 0, 0, 20);
                pnpButton.setTextColor(Color.BLACK);
                pnpButton.setOnClickListener(v -> {
                    try {
                        JSONObject redirectData = new JSONObject(alert.toString());
                        redirectData.put("target_role", "pnp");
                        redirectData.put("emergency_type", emergencyType);
                        redirectData.put("municipality", getMunicipalityFromBarangay(alertBarangay));
                        socket.emit("pnp_redirect_alert", redirectData);
                        typeTextView.setText("Type: " + emergencyType);
                        typeTextView.setVisibility(View.VISIBLE);
                        pnpEmergencyTypeLayout.setVisibility(View.GONE);
                        responseButtonsLayout.setVisibility(View.GONE);
                        socket.emit("update_dashboard_emergency_type", new JSONObject()
                                .put("alert_id", alertId)
                                .put("emergency_type", emergencyType)
                                .put("barangay", alertBarangay.toLowerCase()));
                    } catch (JSONException e) {
                        Log.e("BarangayPage", "Error redirecting PNP alert: " + e.getMessage());
                        Toast.makeText(this, "Error redirecting alert", Toast.LENGTH_SHORT).show();
                    }
                });
                pnpButtons.add(pnpButton);
                pnpEmergencyTypeLayout.addView(pnpButton);
            }

            String[] roles = getResources().getStringArray(R.array.roles_cdrmo_pnp_bfp_cityhealth);
            List<Button> buttons = new ArrayList<>();
            for (String role : roles) {
                Button roleButton = new Button(this);
                roleButton.setText("Send to " + role);
                roleButton.setBackgroundResource(R.drawable.button_background);
                roleButton.setPadding(0, 0, 0, 20);
                roleButton.setTextColor(Color.BLACK);
                roleButton.setOnClickListener(v -> {
                    try {
                        String targetRole = role.toLowerCase();
                        String emergencyType = determineEmergencyType(role);
                        JSONObject redirectData = new JSONObject(alert.toString());
                        redirectData.put("target_role", targetRole);
                        redirectData.put("emergency_type", emergencyType);
                        redirectData.put("municipality", getMunicipalityFromBarangay(alertBarangay));
                        if (targetRole.equals("pnp")) {
                            responseButtonsLayout.setVisibility(View.GONE);
                            pnpEmergencyTypeLayout.setVisibility(View.VISIBLE);
                        } else {
                            socket.emit("redirect_alert", redirectData);
                            typeTextView.setText("Type: " + emergencyType);
                            typeTextView.setVisibility(View.VISIBLE);
                            responseButtonsLayout.setVisibility(View.GONE);
                            socket.emit("update_dashboard_emergency_type", new JSONObject()
                                    .put("alert_id", alertId)
                                    .put("emergency_type", emergencyType)
                                    .put("barangay", alertBarangay.toLowerCase()));
                        }
                    } catch (JSONException e) {
                        Log.e("BarangayPage", "Error redirecting alert: " + e.getMessage());
                        Toast.makeText(this, "Error redirecting alert", Toast.LENGTH_SHORT).show();
                    }
                });
                buttons.add(roleButton);
                responseButtonsLayout.addView(roleButton);
            }

            acceptCheckBox.setOnCheckedChangeListener((buttonView, isChecked) -> {
                if (isChecked) {
                    declineCheckBox.setChecked(false);
                    responseButtonsLayout.setVisibility(View.VISIBLE);
                } else {
                    responseButtonsLayout.setVisibility(View.GONE);
                    pnpEmergencyTypeLayout.setVisibility(View.GONE);
                }
            });

            declineCheckBox.setOnCheckedChangeListener((buttonView, isChecked) -> {
                if (isChecked) {
                    acceptCheckBox.setChecked(false);
                    responseButtonsLayout.setVisibility(View.GONE);
                    pnpEmergencyTypeLayout.setVisibility(View.GONE);
                }
            });

            alertLayout.addView(statusTextView);
            alertLayout.addView(alertText);
            alertLayout.addView(typeTextView);
            alertLayout.addView(timeTextView);
            alertLayout.addView(alertImageView);
            alertLayout.addView(acceptCheckBox);
            alertLayout.addView(declineCheckBox);
            alertLayout.addView(responseButtonsLayout);
            alertLayout.addView(pnpEmergencyTypeLayout);

            alertsContainer.addView(alertLayout, 0);
        } catch (JSONException e) {
            Log.e("BarangayPage", "Error displaying alert: " + e.getMessage());
            Toast.makeText(this, "Error displaying alert", Toast.LENGTH_SHORT).show();
        }
    }

    private String determineEmergencyType(String role) {
        switch (role.toLowerCase()) {
            case "cdrrmo":
                return "Road Accident";
            case "bfp":
                return "Fire Incident";
            case "health":
                return "Health Emergency";
            case "hospital":
                return "Health Emergency";
            default:
                return "Unknown";
        }
    }

    private String getMunicipalityFromBarangay(String barangay) {
        return "San Pablo City";
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
            socket.off();
        }
        if (mediaPlayer != null) {
            mediaPlayer.release();
            mediaPlayer = null;
        }
    }
}