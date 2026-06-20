package com.example.alertnow;

import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import android.widget.Button;

public class LoginType extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.logintype);

        Button residentBtn = findViewById(R.id.resident_button);
        Button cdrrmoBtn = findViewById(R.id.cdrrmo_button);


        residentBtn.setOnClickListener(v -> startActivity(new Intent(this, LoginPage.class)));
        cdrrmoBtn.setOnClickListener(v -> startActivity(new Intent(this, AgencyIn.class)));

    }
}