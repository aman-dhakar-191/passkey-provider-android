# The app uses no reflection of its own; AndroidX and Play Services ship their own consumer rules.

# Minification is currently off (see app/build.gradle.kts). If it is turned back on, these classes are
# instantiated by reflection at app start and must keep their no-arg constructors:
-keep class * extends androidx.room.RoomDatabase { <init>(); }
-keep class * implements com.google.firebase.components.ComponentRegistrar { <init>(); }
