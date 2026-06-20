package com.example.alertnow;

import android.content.Context;
import android.util.Log;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.Map;



public class CoordinatesUtil {
    private static Map<String, double[]> barangayMap;
    private static Map<String, double[]> municipalityMap;
    private static boolean coordinatesLoaded = false;

    public static synchronized void loadCoordinates(Context context) {
        if (coordinatesLoaded) return; // Prevent reloading if already loaded

        barangayMap = new HashMap<>();
        municipalityMap = new HashMap<>();
        try {
            InputStream is = context.getResources().openRawResource(R.raw.coords);
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(",");
                if (parts.length == 4) {
                    String type = parts[0].trim();
                    String name = parts[1].trim();
                    double lat = Double.parseDouble(parts[2].trim());
                    double lon = Double.parseDouble(parts[3].trim());
                    if (type.equals("barangay")) {
                        barangayMap.put(name, new double[]{lat, lon});
                    } else if (type.equals("municipality")) {
                        municipalityMap.put(name, new double[]{lat, lon});
                    }
                }
            }
            reader.close();
            is.close();
            coordinatesLoaded = true;
            Log.d("CoordinatesUtil", "Coordinates loaded successfully from coords file");
        } catch (Exception e) {
            Log.e("CoordinatesUtil", "Error loading coordinates: " + e.getMessage());
            // Fallback to hardcoded defaults
            barangayMap.put("Barangay San Antonio", new double[]{14.0667, 121.3267});
            barangayMap.put("Barangay Santa Cruz", new double[]{14.0625, 121.3208});
            municipalityMap.put("San Pablo City", new double[]{14.0642, 121.3233});
            municipalityMap.put("Quezon Province", new double[]{13.9347, 121.9473});
            coordinatesLoaded = true; // Mark as loaded even with fallback
            Log.w("CoordinatesUtil", "Using fallback coordinates due to loading failure");
        }
    }

    public static double[] getBarangayCoordinates(Context context, String barangay) {
        if (!coordinatesLoaded) {
            loadCoordinates(context);
        }
        if (barangay != null && barangayMap.containsKey(barangay)) {
            double[] coords = barangayMap.get(barangay);
            Log.d("CoordinatesUtil", "Retrieved coordinates for barangay " + barangay + ": [" + coords[0] + ", " + coords[1] + "]");
            return coords;
        } else {
            Log.w("CoordinatesUtil", "Barangay not found: " + barangay + ", returning default Manila coordinates");
            return new double[]{14.5995, 120.9842}; // Default Manila
        }
    }

    public static double[] getMunicipalityCoordinates(Context context, String municipality) {
        if (!coordinatesLoaded) {
            loadCoordinates(context);
        }
        if (municipality != null && municipalityMap.containsKey(municipality)) {
            double[] coords = municipalityMap.get(municipality);
            Log.d("CoordinatesUtil", "Retrieved coordinates for municipality " + municipality + ": [" + coords[0] + ", " + coords[1] + "]");
            return coords;
        } else {
            Log.w("CoordinatesUtil", "Municipality not found: " + municipality + ", returning default Manila coordinates");
            return new double[]{14.5995, 120.9842}; // Default Manila
        }
    }

    public static boolean areCoordinatesLoaded() {
        return coordinatesLoaded;
    }
}