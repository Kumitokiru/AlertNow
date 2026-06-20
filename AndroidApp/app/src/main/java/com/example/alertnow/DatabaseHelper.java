package com.example.alertnow;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;
import org.json.JSONObject;
import io.socket.client.Socket;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;
import org.json.JSONObject;
import io.socket.client.Socket;

public class DatabaseHelper extends SQLiteOpenHelper {
    private static final String DATABASE_NAME = "AlertNowLocal.db";
    private static final int DATABASE_VERSION = 4;
    public static final String TABLE_USERS = "users";
    public static final String TABLE_ALERTS = "alerts";
    public static final String TABLE_RESPONSES = "responses";
    private static final String TAG = "DatabaseHelper";
    private static final String USERS_CREATE = "CREATE TABLE " + TABLE_USERS + " (" +
            "username TEXT PRIMARY KEY, password TEXT NOT NULL, role TEXT NOT NULL, " +
            "first_name TEXT, middle_name TEXT, last_name TEXT, age INTEGER, " +
            "contact_no TEXT, house_no TEXT, street_no TEXT, barangay TEXT, " +
            "municipality TEXT, province TEXT, position TEXT, assigned_hospital TEXT, synced INTEGER DEFAULT 0);";
    private static final String ALERTS_CREATE = "CREATE TABLE " + TABLE_ALERTS + " (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL, synced INTEGER DEFAULT 0);";
    private static final String RESPONSES_CREATE = "CREATE TABLE " + TABLE_RESPONSES + " (" +
            "id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL, synced INTEGER DEFAULT 0);";

    public DatabaseHelper(Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL(USERS_CREATE);
        db.execSQL(ALERTS_CREATE);
        db.execSQL(RESPONSES_CREATE);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        if (oldVersion < 3) {
            db.execSQL(ALERTS_CREATE);
            db.execSQL(RESPONSES_CREATE);
        }
        if (oldVersion < 4) {
            db.execSQL("ALTER TABLE " + TABLE_USERS + " ADD COLUMN assigned_hospital TEXT");
        }
    }

    public boolean insertUser(ContentValues values) {
        SQLiteDatabase db = this.getWritableDatabase();
        long result = db.insertWithOnConflict(TABLE_USERS, null, values, SQLiteDatabase.CONFLICT_IGNORE);
        db.close();
        return result != -1;
    }

    public void storeResponse(JSONObject response) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put("data", response.toString());
        values.put("synced", 0);
        db.insert(TABLE_RESPONSES, null, values);
        db.close();
    }

    public String getUserRoleByUsernamePassword(String username, String password) {
        SQLiteDatabase db = null;
        Cursor cursor = null;
        try {
            db = this.getReadableDatabase();
            String[] columns = {"role"};
            String selection = "username = ? AND password = ?";
            String[] selectionArgs = {username, password};
            cursor = db.query(TABLE_USERS, columns, selection, selectionArgs, null, null, null);
            if (cursor.moveToFirst()) {
                String role = cursor.getString(cursor.getColumnIndexOrThrow("role"));
                Log.d(TAG, "Found role for username " + username + ": " + role);
                return role;
            }
            Log.w(TAG, "No user found for username: " + username);
            return null;
        } catch (Exception e) {
            Log.e(TAG, "Error getting role for username " + username + ": " + e.getMessage(), e);
            return null;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            if (db != null) {
                db.close();
            }
        }
    }

    public String getUserRoleByMunicipalityContactNoPassword(String role, String municipality, String contactNo, String password) {
        SQLiteDatabase db = null;
        Cursor cursor = null;
        try {
            db = this.getReadableDatabase();
            String[] columns = {"role"};
            String selection = "role = ? AND municipality = ? AND contact_no = ? AND password = ?";
            String[] selectionArgs = {role, municipality, contactNo, password};
            cursor = db.query(TABLE_USERS, columns, selection, selectionArgs, null, null, null);
            if (cursor.moveToFirst()) {
                String userRole = cursor.getString(cursor.getColumnIndexOrThrow("role"));
                Log.d(TAG, "Found role for contact_no " + contactNo + ": " + userRole);
                return userRole;
            }
            Log.w(TAG, "No user found for contact_no: " + contactNo);
            return null;
        } catch (Exception e) {
            Log.e(TAG, "Error getting role for contact_no " + contactNo + ": " + e.getMessage(), e);
            return null;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            if (db != null) {
                db.close();
            }
        }
    }

    public String getAssignedHospitalByMunicipalityContactNoPassword(String role, String municipality, String contactNo, String password) {
        SQLiteDatabase db = null;
        Cursor cursor = null;
        try {
            db = this.getReadableDatabase();
            String[] columns = {"assigned_hospital"};
            String selection = "role = ? AND municipality = ? AND contact_no = ? AND password = ?";
            String[] selectionArgs = {role, municipality, contactNo, password};
            cursor = db.query(TABLE_USERS, columns, selection, selectionArgs, null, null, null);
            if (cursor.moveToFirst()) {
                String assignedHospital = cursor.getString(cursor.getColumnIndexOrThrow("assigned_hospital"));
                Log.d(TAG, "Found assigned_hospital for contact_no " + contactNo + ": " + assignedHospital);
                return assignedHospital;
            }
            Log.w(TAG, "No assigned_hospital found for contact_no: " + contactNo);
            return null;
        } catch (Exception e) {
            Log.e(TAG, "Error getting assigned_hospital for contact_no " + contactNo + ": " + e.getMessage(), e);
            return null;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            if (db != null) {
                db.close();
            }
        }
    }

    public String getHouseNoByUsername(String username) {
        SQLiteDatabase db = null;
        Cursor cursor = null;
        try {
            db = this.getReadableDatabase();
            String[] columns = {"house_no"};
            String selection = "username = ?";
            String[] selectionArgs = {username};
            cursor = db.query(TABLE_USERS, columns, selection, selectionArgs, null, null, null);
            if (cursor.moveToFirst()) {
                String houseNo = cursor.getString(cursor.getColumnIndexOrThrow("house_no"));
                Log.d(TAG, "Found house_no for username " + username + ": " + houseNo);
                return houseNo;
            }
            Log.w(TAG, "No house_no found for username: " + username);
            return null;
        } catch (Exception e) {
            Log.e(TAG, "Error getting house_no for username " + username + ": " + e.getMessage(), e);
            return null;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            if (db != null) {
                db.close();
            }
        }
    }

    public String getStreetNoByUsername(String username) {
        SQLiteDatabase db = null;
        Cursor cursor = null;
        try {
            db = this.getReadableDatabase();
            String[] columns = {"street_no"};
            String selection = "username = ?";
            String[] selectionArgs = {username};
            cursor = db.query(TABLE_USERS, columns, selection, selectionArgs, null, null, null);
            if (cursor.moveToFirst()) {
                String streetNo = cursor.getString(cursor.getColumnIndexOrThrow("street_no"));
                Log.d(TAG, "Found street_no for username " + username + ": " + streetNo);
                return streetNo;
            }
            Log.w(TAG, "No street_no found for username: " + username);
            return null;
        } catch (Exception e) {
            Log.e(TAG, "Error getting street_no for username " + username + ": " + e.getMessage(), e);
            return null;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            if (db != null) {
                db.close();
            }
        }
    }

    public String getUserRole(String role, String municipality, String contactNo, String password) {
        SQLiteDatabase db = this.getReadableDatabase();
        String[] columns = {"role"};
        String selection = "role = ? AND municipality = ? AND contact_no = ? AND password = ?";
        String[] selectionArgs = {role, municipality, contactNo, password};

        Cursor cursor = db.query(TABLE_USERS, columns, selection, selectionArgs, null, null, null);
        String userRole = null;

        if (cursor.moveToFirst()) {
            userRole = cursor.getString(cursor.getColumnIndexOrThrow("role"));
        }
        cursor.close();
        db.close();
        return userRole;
    }

    public Cursor getUserByUsername(String username) {
        SQLiteDatabase db = this.getReadableDatabase();
        String[] columns = {"house_no", "street_no", "barangay"};
        String selection = "username = ?";
        String[] selectionArgs = {username};
        return db.query(TABLE_USERS, columns, selection, selectionArgs, null, null, null);
    }

    public String getBarangayByUsername(String username) {
        SQLiteDatabase db = null;
        Cursor cursor = null;
        try {
            db = this.getReadableDatabase();
            String[] columns = {"barangay"};
            String selection = "username = ?";
            String[] selectionArgs = {username};
            cursor = db.query(TABLE_USERS, columns, selection, selectionArgs, null, null, null);
            if (cursor.moveToFirst()) {
                String barangay = cursor.getString(cursor.getColumnIndexOrThrow("barangay"));
                Log.d(TAG, "Found barangay for username " + username + ": " + barangay);
                return barangay;
            }
            Log.w(TAG, "No barangay found for username: " + username);
            return null;
        } catch (Exception e) {
            Log.e(TAG, "Error getting barangay for username " + username + ": " + e.getMessage(), e);
            return null;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            if (db != null) {
                db.close();
            }
        }
    }

    public void insertAlert(String alertData) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put("data", alertData);
        values.put("synced", 0);
        db.insert(TABLE_ALERTS, null, values);
        db.close();
    }

    public JSONObject getLatestAlert() {
        SQLiteDatabase db = this.getReadableDatabase();
        Cursor cursor = db.query(TABLE_ALERTS, new String[]{"data"}, null, null, null, null, "id DESC", "1");
        if (cursor.moveToFirst()) {
            String alertData = cursor.getString(cursor.getColumnIndexOrThrow("data"));
            try {
                return new JSONObject(alertData);
            } catch (Exception e) {
                Log.e("DatabaseHelper", "Error parsing latest alert: " + e.getMessage());
            }
        }
        cursor.close();
        db.close();
        return null;
    }

    public Cursor getUnsyncedUsers() {
        SQLiteDatabase db = this.getReadableDatabase();
        return db.query(TABLE_USERS, null, "synced = 0", null, null, null, null);
    }

    public void updateSyncStatus(String username, int synced) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put("synced", synced);
        db.update(TABLE_USERS, values, "username = ?", new String[]{username});
        db.close();
    }

    public Cursor getUsersByRoles(String... roles) {
        SQLiteDatabase db = this.getReadableDatabase();
        StringBuilder query = new StringBuilder("SELECT role, municipality, contact_no, password, assigned_hospital FROM users WHERE role IN (");
        for (int i = 0; i < roles.length; i++) {
            query.append("?");
            if (i < roles.length - 1) query.append(",");
        }
        query.append(")");
        return db.rawQuery(query.toString(), roles);
    }

    public Cursor getAllUsers() {
        SQLiteDatabase db = this.getReadableDatabase();
        return db.rawQuery("SELECT * FROM users", null);
    }

    public void storeAlert(JSONObject alert) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put("data", alert.toString());
        values.put("synced", 0);
        db.insert("alerts", null, values);
        db.close();
    }

    public void syncAlerts(Socket socket) {
        SQLiteDatabase db = this.getWritableDatabase();
        Cursor cursor = db.query(TABLE_ALERTS, new String[]{"id", "data"}, "synced = 0", null, null, null, null);

        while (cursor.moveToNext()) {
            int id = cursor.getInt(cursor.getColumnIndexOrThrow("id"));
            String data = cursor.getString(cursor.getColumnIndexOrThrow("data"));
            try {
                JSONObject alert = new JSONObject(data);
                if (socket != null && socket.connected()) {
                    socket.emit("alert", alert);
                    ContentValues values = new ContentValues();
                    values.put("synced", 1);
                    db.update(TABLE_ALERTS, values, "id = ?", new String[]{String.valueOf(id)});
                    Log.d("DatabaseHelper", "Synced alert with ID: " + id);
                } else {
                    Log.e("DatabaseHelper", "Socket not connected, cannot sync alert ID: " + id);
                }
            } catch (Exception e) {
                Log.e("DatabaseHelper", "Error syncing alert ID " + id + ": " + e.getMessage());
            }
        }

        cursor.close();
        db.close();
    }
}