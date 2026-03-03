plugins {
     id("com.android.application")
     id("org.jetbrains.kotlin.android")
 }
 android {
     namespace = "com.factorykeycheck.demo"
     compileSdk = 33
     defaultConfig {
         applicationId = "com.factorykeycheck.demo"
         minSdk = 24
         targetSdk = 33
         versionCode = 1
         versionName = "1.0"
     }
     compileOptions {
         sourceCompatibility = JavaVersion.VERSION_1_8
         targetCompatibility = JavaVersion.VERSION_1_8
     }
     kotlinOptions {
         jvmTarget = "1.8"
     }
 }
 dependencies {
     implementation("androidx.core:core-ktx:1.7.0")
     implementation("androidx.appcompat:appcompat:1.6.1")
     implementation("com.google.android.attestation:attestation:1.2.0")
 }