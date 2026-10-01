plugins {
    id("com.android.application")
}

android {
    namespace = "it.leonardo.antivirus"
    compileSdk = 34

    defaultConfig {
        applicationId = "it.leonardo.antivirus"
        minSdk = 29
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
