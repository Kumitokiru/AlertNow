# Keep Socket.IO classes
-keep class io.socket.** { *; }
-dontwarn io.socket.**

# Keep JSON-related classes
-keep class org.json.** { *; }
-dontwarn org.json.**

# Preserve native methods and enums
-keepclassmembers class * {
    native <methods>;
}
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Preserve annotations
-keepattributes *Annotation*

# If you use custom models or parcels
-keep class com.example.alertnow.** { *; }