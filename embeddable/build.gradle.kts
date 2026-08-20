plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "org.matrix.teesim.embedded"
    compileSdk = 36
    ndkVersion = "28.2.13676358"
    buildToolsVersion = "36.0.0"

    defaultConfig {
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "4.0-embedded"
        externalNativeBuild {
            cmake {
                abiFilters += listOf("arm64-v8a", "x86_64")
                targets += listOf("teesim_embedded")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildFeatures {
        buildConfig = false
        resValues = false
    }

    lint { abortOnError = false }

    externalNativeBuild {
        cmake {
            path = projectDir.resolve("src/main/cpp/CMakeLists.txt")
            buildStagingDirectory = layout.buildDirectory.get().asFile
        }
    }
}

dependencies {
    // No external dependencies — the TA is self-contained
}