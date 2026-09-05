plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.detekt)
}

android {
    namespace = "com.example.torchatv2.transport"
    compileSdk = 37
    defaultConfig {
        minSdk = 26
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation(project(":protocol"))
    implementation(project(":domain"))
    implementation(project(":crypto"))
    implementation(project(":common"))
    implementation(libs.kotlinx.coroutines.core)
    
    // Tor implementation
    implementation(libs.torandroid)
    implementation(libs.jtorctl)

    testImplementation(libs.junit)
}

detekt {
    buildUponDefaultConfig = true
    allRules = false
    config.setFrom(files("$rootDir/config/detekt/detekt.yml"))
}
