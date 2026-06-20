package com.example.alertnow;

import android.widget.ImageView;
import com.bumptech.glide.Glide;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.util.Base64;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.Gson;
import com.squareup.picasso.Picasso;
import com.squareup.picasso.Callback;

public class Util {
    public static void loadImageIntoView(String url, ImageView imageView) {
        Picasso.get().load(url).into(imageView, new Callback() {
            @Override
            public void onSuccess() {
                Log.d("Util", "Image loaded successfully from: " + url);
            }
            @Override
            public void onError(Exception e) {
                Log.e("Util", "Error loading image: " + e.getMessage());
            }
        });
    }

    public static void loadBase64IntoView(String base64, ImageView imageView) {
        byte[] decodedString = Base64.decode(base64, Base64.DEFAULT);
        Bitmap decodedByte = BitmapFactory.decodeByteArray(decodedString, 0, decodedString.length);
        imageView.setImageBitmap(decodedByte);
    }
}


