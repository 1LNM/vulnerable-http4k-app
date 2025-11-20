package com.example.routes

import org.http4k.core.*
import org.http4k.lens.*

/**
 * VULNERABILITY: Command Injection via LensExtractor.get()
 *
 * Expected Detection:
 * - Query: java/command-injection
 * - Source: LensExtractor.get()
 * - Sink: Runtime.exec()
 *
 * Data Flow: LensExtractor.get() -> command execution
 */
fun commandInjectionLensGetEndpoint(request: Request): Response {
    // SOURCE: User input via LensExtractor.get()
    val hostLens = Query.required("host")
    val host = hostLens.get(request)

    return try {
        // SINK: Command injection vulnerability
        val process = Runtime.getRuntime().exec(arrayOf("ping", "-c", "1", host))
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        Response(Status.OK).body("Exit code: $exitCode\n\nOutput:\n$output")
    } catch (e: Exception) {
        Response(Status.INTERNAL_SERVER_ERROR).body("Error: \\$\{e.message}")
    }
}

/**
 * VULNERABILITY: Command Injection via Request.header()
 *
 * Expected Detection:
 * - Query: java/command-injection
 * - Source: Request.header()
 * - Sink: Runtime.exec()
 *
 * Data Flow: Request.header() -> command execution
 */
fun commandInjectionRequestHeaderEndpoint(request: Request): Response {
    // SOURCE: User input via Request.header()
    val command = request.header("X-Command") ?: "echo hello"

    return try {
        // SINK: Command injection via shell
        val process = Runtime.getRuntime().exec("sh -c $command")
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        Response(Status.OK).body("Exit code: $exitCode\n\nOutput:\n$output")
    } catch (e: Exception) {
        Response(Status.INTERNAL_SERVER_ERROR).body("Error: \\$\{e.message}")
    }
}

/**
 * VULNERABILITY: Command Injection via HttpMessage.header()
 *
 * Expected Detection:
 * - Query: java/command-injection
 * - Source: HttpMessage.header()
 * - Sink: Runtime.exec()
 *
 * Data Flow: HttpMessage.header() -> command execution
 */
fun commandInjectionHttpMessageHeaderEndpoint(request: Request): Response {
    // SOURCE: User input via HttpMessage.header() (Request extends HttpMessage)
    val target = request.header("X-Target") ?: "localhost"

    return try {
        // SINK: Command injection vulnerability
        val process = Runtime.getRuntime().exec(arrayOf("nslookup", target))
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        Response(Status.OK).body("Exit code: $exitCode\n\nOutput:\n$output")
    } catch (e: Exception) {
        Response(Status.INTERNAL_SERVER_ERROR).body("Error: \\$\{e.message}")
    }
}