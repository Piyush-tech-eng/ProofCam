plugins {
    id("com.android.application")
}

android {
    namespace = "com.proofcam.capture"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.proofcam.capture"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    val cameraX = "1.6.2"
    implementation("androidx.activity:activity:1.13.0")
    implementation("androidx.camera:camera-core:$cameraX")
    implementation("androidx.camera:camera-camera2:$cameraX")
    implementation("androidx.camera:camera-lifecycle:$cameraX")
    implementation("androidx.camera:camera-view:$cameraX")
}
