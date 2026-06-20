package com.example.alertnow; // Replace with your actual package name

import android.app.Application;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;
import androidx.work.ExistingPeriodicWorkPolicy;
import java.util.concurrent.TimeUnit;

public class MainApplication extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        scheduleSync();
    }

    private void scheduleSync() {
        // Define a periodic work request (e.g., every 15 minutes)
        PeriodicWorkRequest syncWork = new PeriodicWorkRequest.Builder(SyncWorker.class, 15, TimeUnit.MINUTES)
                .build();

        // Schedule the work with WorkManager
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
                "syncWork",                // Unique name for the work
                ExistingPeriodicWorkPolicy.KEEP, // Keep existing work if already scheduled
                syncWork                   // The work request to enqueue
        );
    }
}