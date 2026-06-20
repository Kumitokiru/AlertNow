package com.example.alertnow;

import android.graphics.Bitmap;
import java.util.Random;

public class DecisionTreeClassifier {
    public String predict(Bitmap bitmap) {
        // Placeholder: Simulate image classification for fire or road_accident
        // In a real app, implement a decision tree or use a pre-trained model
        int[] pixels = new int[bitmap.getWidth() * bitmap.getHeight()];
        bitmap.getPixels(pixels, 0, bitmap.getWidth(), 0, 0, bitmap.getWidth(), bitmap.getHeight());

        Random rand = new Random();
        int randomValue = rand.nextInt(2);  // Only two options: fire or road_accident
        switch (randomValue) {
            case 0:
                return "fire";
            case 1:
                return "road_accident";
            default:
                return "unknown";
        }
    }
}