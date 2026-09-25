# R8 settings for release builds (and the CI-only "minified" build, which runs the emulator self-test).

# The source is public, so renaming classes hides nothing; keeping names makes the crash screen's stack
# traces readable and lets scripts/check-store-build.sh find the updater classes by name.
-dontobfuscate

# Created by reflection at app start; without these, v1.0.1 crashed on launch.
-keep class * extends androidx.room.RoomDatabase { <init>(); }
-keep class * implements com.google.firebase.components.ComponentRegistrar { <init>(); }
-keepclassmembers class * extends androidx.work.ListenableWorker {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}
