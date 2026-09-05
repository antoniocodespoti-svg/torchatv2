plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.detekt)
}

android {
    namespace = "com.example.torchatv2.architecture"
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
    testImplementation(libs.archunit)
    testImplementation(libs.junit)
    
    // Dipendenze per permettere ad ArchUnit di analizzare le classi se necessario,
    // o semplicemente per garantire che il modulo veda il resto.
    testImplementation(project(":app"))
    testImplementation(project(":presentation"))
    testImplementation(project(":domain"))
    testImplementation(project(":crypto"))
    testImplementation(project(":ratchet"))
    testImplementation(project(":protocol"))
    testImplementation(project(":storage"))
    testImplementation(project(":transport"))
    testImplementation(project(":security"))
    testImplementation(project(":common"))
}

detekt {
    buildUponDefaultConfig = true
    allRules = false
    config.setFrom(files("$rootDir/config/detekt/detekt.yml"))
}
