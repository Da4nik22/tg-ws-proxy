plugins {
    id("com.android.application")
}

android {
    namespace = "dev.personal.tgws"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.personal.tgws"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Personal use: sign the release build with the debug key so it installs without a keystore.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
