plugins {
    kotlin("jvm") version "1.9.22"
    application
}

group = "com.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    // http4k core dependencies
    implementation("org.http4k:http4k-core:5.13.0.0")
    implementation("org.http4k:http4k-server-netty:5.13.0.0")

    // For SQL injection demo
    implementation("com.h2database:h2:2.2.224")

    // Kotlin standard library
    implementation(kotlin("stdlib"))
}

application {
    mainClass.set("com.example.VulnerableAppKt")
}

kotlin {
    jvmToolchain(17)
}

// Disable test task
tasks.named("test") {
    enabled = false
}

dependencyLocking {
    lockAllConfigurations()
}