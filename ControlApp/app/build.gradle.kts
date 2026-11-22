plugins {
    alias(libs.plugins.android.application)
    id("com.google.gms.google-services")
}

android {
    namespace = "com.example.aplicacioncontrolada"
    compileSdk {
        version = release(37)
    }

    defaultConfig {
        applicationId = "com.example.aplicacioncontrolada"
        minSdk = 33
        targetSdk = 37
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            optimization {
                enable = true
                packageScope = setOf("androidx.**", "kotlin.**", "kotlinx.**")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

dependencies {
    implementation(libs.androidx.activity.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.androidx.core.ktx)
    implementation(libs.material)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
// 1. Google Analytics for Firebase
    implementation(platform("com.google.firebase:firebase-bom:33.1.0"))
    implementation("com.google.firebase:firebase-analytics")

    // 2. Facebook Android SDK (Core / App Events)
    implementation("com.facebook.android:facebook-android-sdk:17.0.0")

    // 3. Google AdMob (Mobile Ads SDK)
    implementation("com.google.android.gms:play-services-ads:23.2.0")

    // Servicios de ubicación (para probar la transmisión de coordenadas)
    implementation("com.google.android.gms:play-services-location:21.3.0")

}