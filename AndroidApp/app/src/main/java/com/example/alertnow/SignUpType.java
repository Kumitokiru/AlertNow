package com.example.alertnow;

import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import android.widget.Button;

public class SignUpType extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.signuptype);

        Button residentBtn = findViewById(R.id.resident_button);
        Button cdrmoBtn = findViewById(R.id.cdrmo_button);


        residentBtn.setOnClickListener(v -> startActivity(new Intent(this, SignupPage.class)));
        cdrmoBtn.setOnClickListener(v -> startActivity(new Intent(this, Agencyup.class)));

    }
}