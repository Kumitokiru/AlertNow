package com.example.alertnow;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Bundle;
import android.provider.MediaStore;
import android.util.Base64;
import android.util.Log;
import android.widget.Button;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import com.google.android.gms.location.FusedLocationProviderClient;
import com.google.android.gms.location.LocationServices;

import org.json.JSONException;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import io.socket.client.IO;
import io.socket.client.Socket;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import android.view.View;

import android.widget.ImageView;
import androidx.core.content.ContextCompat;
import android.content.SharedPreferences;


import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.view.ViewGroup;

import android.widget.RelativeLayout;




public class ResidentPage extends AppCompatActivity {
    private Socket socket;
    private Button alertButton, uploadPhotoButton, logoutButton;
    private ImageView mapView, photoView;
    private FusedLocationProviderClient fusedLocationClient;
    private String imageBase64;
    private DatabaseHelper dbHelper;
    private SharedPreferences prefs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.residentpage);

        prefs = getSharedPreferences("AlertNowPrefs", MODE_PRIVATE);
        String savedUsername = prefs.getString("username", null);
        String savedRole = prefs.getString("role", null);
        if (savedUsername == null || savedRole == null || !savedRole.equals("resident")) {
            Toast.makeText(this, "Please log in", Toast.LENGTH_SHORT).show();
            startActivity(new Intent(this, LoginPage.class));
            finish();
            return;
        }

        dbHelper = new DatabaseHelper(this);

        fusedLocationClient = LocationServices.getFusedLocationProviderClient(this);

        alertButton = findViewById(R.id.alertButton);
        uploadPhotoButton = findViewById(R.id.uploadPhotoButton);
        photoView = findViewById(R.id.photoView);
        logoutButton = findViewById(R.id.layas);

        alertButton.setOnClickListener(v -> {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, 100);
            } else {
                getLocationAndSendAlert();
            }
        });

        uploadPhotoButton.setOnClickListener(v -> {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.CAMERA}, 2);
            } else {
                openCamera();
            }
        });

        logoutButton.setOnClickListener(v -> {
            socket.disconnect();
            startActivity(new Intent(this, LoginPage.class));
            finish();
        });

        initializeSocket();
    }


    private void initializeSocket() {
        try {
            socket = IO.socket("https://alertnow-wi0n.onrender.com");
            socket.on(Socket.EVENT_CONNECT, args -> {
                Log.d("ResidentPage", "Socket connected");
                try {
                    socket.emit("register_role", new JSONObject()
                            .put("role", "resident")
                            .put("barangay", prefs.getString("barangay", "").toLowerCase()));
                } catch (org.json.JSONException e) {
                    Log.e("ResidentPage", "JSON error in socket connect: " + e.getMessage());
                }
            }).on("new_alert", args -> {
                Log.d("ResidentPage", "Received new_alert: " + args[0].toString());
                try {
                    JSONObject alert = (JSONObject) args[0];
                    if (!alert.has("image")) {
                        runOnUiThread(() -> {
                            try {
                                socket.emit("forward_alert", new JSONObject()
                                        .put("alert_id", alert.getString("alert_id"))
                                        .put("role", "barangay")
                                        .put("barangay", prefs.getString("barangay", "").toLowerCase()));
                            } catch (JSONException e) {
                                throw new RuntimeException(e);
                            }
                        });
                    }
                } catch (Exception e) {
                    Log.e("ResidentPage", "Error processing new_alert: " + e.getMessage());
                }
            }).on(Socket.EVENT_DISCONNECT, args -> {
                Log.d("ResidentPage", "Socket disconnected, attempting to reconnect");
                socket.connect();
            }).on(Socket.EVENT_CONNECT_ERROR, args -> Log.e("ResidentPage", "Connection error: " + args[0]));
            socket.connect();
        } catch (Exception e) {
            Log.e("ResidentPage", "Socket initialization failed: " + e.getMessage());
        }
    }

    private void getLocationAndSendAlert() {
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED && ActivityCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            // TODO: Consider calling
            //    ActivityCompat#requestPermissions
            // here to request the missing permissions, and then overriding
            //   public void onRequestPermissionsResult(int requestCode, String[] permissions,
            //                                          int[] grantResults)
            // to handle the case where the user grants the permission. See the documentation
            // for ActivityCompat#requestPermissions for more details.
            return;
        }
        fusedLocationClient.getLastLocation()
                .addOnSuccessListener(this, location -> {
                    if (location != null) {
                        double lat = location.getLatitude();
                        double lon = location.getLongitude();
                        try {
                            JSONObject alert = new JSONObject();
                            alert.put("lat", lat);
                            alert.put("lon", lon);
                            alert.put("house_no", prefs.getString("house_no", "N/A"));
                            alert.put("street_no", prefs.getString("street_no", "N/A"));
                            alert.put("barangay", prefs.getString("barangay", ""));
                            alert.put("emergency_type", "Emergency");
                            alert.put("timestamp", new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date()));
                            if (imageBase64 != null) {
                                alert.put("image", imageBase64);
                            }

                            if (isNetworkAvailable()) {
                                socket.emit("alert", alert);
                                Toast.makeText(ResidentPage.this, "Alert Sent Successfully", Toast.LENGTH_SHORT).show();
                                Log.d("ResidentPage", "Alert emitted: " + alert.toString());
                            } else {
                                dbHelper.storeAlert(alert);
                                Toast.makeText(ResidentPage.this, "No network, alert stored locally", Toast.LENGTH_SHORT).show();
                                Log.d("ResidentPage", "Alert stored locally: " + alert.toString());
                            }

                            Intent intent = new Intent("com.example.alertnow.NEW_ALERT");
                            intent.putExtra("alert_data", alert.toString());
                            LocalBroadcastManager.getInstance(ResidentPage.this).sendBroadcast(intent);
                        } catch (Exception e) {
                            Log.e("ResidentPage", "Error sending alert: " + e.getMessage());
                            Toast.makeText(ResidentPage.this, "Failed to Send Alert", Toast.LENGTH_SHORT).show();
                        }
                    } else {
                        Toast.makeText(this, "Unable to get location", Toast.LENGTH_SHORT).show();
                    }
                });
    }

    private void openCamera() {
        Intent cameraIntent = new Intent(MediaStore.ACTION_IMAGE_CAPTURE);
        if (cameraIntent.resolveActivity(getPackageManager()) != null) {
            startActivityForResult(cameraIntent, 1);
        } else {
            Toast.makeText(this, "Camera not available", Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == 100) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                getLocationAndSendAlert();
            } else {
                Toast.makeText(this, "Location permission denied", Toast.LENGTH_SHORT).show();
            }
        } else if (requestCode == 2) {  // CAMERA
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                openCamera();
            } else {
                Toast.makeText(this, "Camera permission denied", Toast.LENGTH_SHORT).show();
            }
        }
    }



    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode == RESULT_OK && data != null) {
            try {
                Bitmap bitmap;
                if (requestCode == 1) { // Camera
                    bitmap = (Bitmap) data.getExtras().get("data");
                } else { // Gallery
                    Uri selectedImage = data.getData();
                    bitmap = MediaStore.Images.Media.getBitmap(getContentResolver(), selectedImage);
                }
                imageBase64 = bitmapToBase64(bitmap);
                photoView.setImageBitmap(bitmap);
                photoView.setVisibility(View.VISIBLE);
                startTimer();
            } catch (Exception e) {
                Log.e("ResidentPage", "Error processing photo: " + e.getMessage());
            }
        }
    }

    private void startTimer() {
        new android.os.CountDownTimer(30000, 1000) {
            public void onTick(long millisUntilFinished) {}
            public void onFinish() {
                imageBase64 = null;
                photoView.setVisibility(View.GONE);
                Toast.makeText(ResidentPage.this, "Time's up! Photo discarded.", Toast.LENGTH_SHORT).show();
            }
        }.start();
    }

    private String bitmapToBase64(Bitmap bitmap) {
        int width = bitmap.getWidth();
        int height = bitmap.getHeight();
        int newWidth = 800;
        int newHeight = (int) (height * (800.0 / width));
        Bitmap resizedBitmap = Bitmap.createScaledBitmap(bitmap, newWidth, newHeight, true);

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        resizedBitmap.compress(Bitmap.CompressFormat.JPEG, 80, byteArrayOutputStream);
        byte[] byteArray = byteArrayOutputStream.toByteArray();
        String base64 = Base64.encodeToString(byteArray, Base64.NO_WRAP);
        Log.d("ResidentPage", "Image size: " + base64.length());
        return base64;
    }



    private boolean isNetworkAvailable() {
        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = cm.getActiveNetworkInfo();
        return networkInfo != null && networkInfo.isConnected();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (socket != null) {
            socket.disconnect();
        }
    }
}