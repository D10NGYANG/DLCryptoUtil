plugins {
    kotlin("multiplatform") version "1.9.0"
    id("com.github.ben-manes.versions") version "0.47.0"
}

group = "com.github.D10NGYANG"
version = "0.0.1"

repositories {
    mavenCentral()
}

kotlin {
    jvm {
        jvmToolchain(8)
        withJava()
    }
    js(IR) {
        moduleName = "dl-crypto-util"
        binaries.library()
        binaries.executable()
        nodejs()
        generateTypeScriptDefinitions()
    }

    
    sourceSets {
        val commonMain by getting
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
        val jvmMain by getting {
            dependencies {
                implementation("org.bouncycastle:bcprov-jdk15on:1.70")
                implementation("org.bouncycastle:bcpkix-jdk15on:1.70")
            }
        }
        val jvmTest by getting
        val jsMain by getting {
            dependencies {
                implementation(npm("node-forge", "1.3.1"))
            }
        }
        val jsTest by getting
    }
}

fun isNonStable(version: String): Boolean {
    val stableKeyword = listOf("RELEASE", "FINAL", "GA").any { version.uppercase().contains(it) }
    val regex = "^[0-9,.v-]+(-r)?$".toRegex()
    val isStable = stableKeyword || regex.matches(version)
    return isStable.not()
}

tasks.withType<com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask> {
    rejectVersionIf {
        isNonStable(candidate.version)
    }
}
