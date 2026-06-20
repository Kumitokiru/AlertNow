package com.example.alertnow;

import android.app.IntentService;
import android.content.Intent;
import android.database.Cursor;
import android.os.Handler;
import android.os.Looper;
import android.widget.Toast;
import org.json.JSONObject;
import java.io.IOException;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.MediaType;
import okhttp3.Response;

public class SyncService extends IntentService {
    private static final String[] SERVER_URLS = {"https://alertnow-cgre.onrender.com/sync"};
    private DatabaseHelper dbHelper;
    private OkHttpClient client;

    public SyncService() {
        super("SyncService");
    }

    @Override
    public void onCreate() {
        super.onCreate();
        dbHelper = new DatabaseHelper(this);
        client = new OkHttpClient();
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        Cursor cursor = dbHelper.getUnsyncedUsers();
        if (cursor != null && cursor.moveToFirst()) {
            do {
                String username = cursor.getString(cursor.getColumnIndexOrThrow("username"));
                syncUser(username);
            } while (cursor.moveToNext());
            cursor.close();
        }
    }

    private void syncUser(String username) {
        Cursor cursor = dbHelper.getUnsyncedUsers();
        if (cursor != null && cursor.moveToFirst()) {
            JSONObject userData = new JSONObject();
            try {
                do {
                    int usernameIndex = cursor.getColumnIndex("username");
                    if (usernameIndex >= 0 && cursor.getString(usernameIndex).equals(username)) {
                        putIfColumnExists(userData, cursor, "username");
                        putIfColumnExists(userData, cursor, "password");
                        putIfColumnExists(userData, cursor, "role");
                        putIfColumnExists(userData, cursor, "barangay");
                        putIfColumnExists(userData, cursor, "municipality");
                        putIfColumnExists(userData, cursor, "province");
                        putIfColumnExists(userData, cursor, "contact_no");
                        putIfColumnExists(userData, cursor, "first_name");
                        putIfColumnExists(userData, cursor, "middle_name");
                        putIfColumnExists(userData, cursor, "last_name");
                        putIfColumnExists(userData, cursor, "age");
                        putIfColumnExists(userData, cursor, "house_no");
                        putIfColumnExists(userData, cursor, "street_no");
                        putIfColumnExists(userData, cursor, "position");
                        break;
                    }
                } while (cursor.moveToNext());

                RequestBody body = RequestBody.create(
                        MediaType.parse("application/json; charset=utf-8"), userData.toString());

                for (String url : SERVER_URLS) {
                    Request request = new Request.Builder()
                            .url(url)
                            .post(body)
                            .build();

                    try (Response response = client.newCall(request).execute()) {
                        if (response.isSuccessful()) {
                            dbHelper.updateSyncStatus(username, 1);
                            showToast("User " + username + " synced with " + url);
                            break;
                        }
                    } catch (IOException e) {
                        // Continue to next server on failure
                    }
                }
            } catch (Exception e) {
                showToast("Sync failed for " + username + ": " + e.getMessage());
            } finally {
                cursor.close();
            }
        }
    }

    private void putIfColumnExists(JSONObject userData, Cursor cursor, String columnName) throws Exception {
        int columnIndex = cursor.getColumnIndex(columnName);
        if (columnIndex >= 0 && !cursor.isNull(columnIndex)) {
            if (columnName.equals("age")) {
                userData.put(columnName, cursor.getInt(columnIndex));
            } else {
                userData.put(columnName, cursor.getString(columnIndex));
            }
        }
    }

    private void showToast(final String message) {
        new Handler(Looper.getMainLooper()).post(() -> Toast.makeText(this, message, Toast.LENGTH_SHORT).show());
    }
}