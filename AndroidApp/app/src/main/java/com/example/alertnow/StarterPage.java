package com.example.alertnow;

import android.content.Intent;
import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import android.widget.Button;

public class StarterPage extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.starterpage);


        Button signUpBtn = findViewById(R.id.signUpButton);
        Button logInBtn = findViewById(R.id.logInButton);


        signUpBtn.setOnClickListener(v -> startActivity(new Intent(this, SignUpType.class)));
        logInBtn.setOnClickListener(v -> startActivity(new Intent(this, LoginType.class)));
    }
}