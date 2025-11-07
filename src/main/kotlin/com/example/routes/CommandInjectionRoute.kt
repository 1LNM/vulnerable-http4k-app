package com.example.routes

import org.http4k.core.*
import org.http4k.lens.*

/**
 * VULNERABILITY: Command Injection via Runtime.exec()
 *
 * Expected Detection:
 * - Query: java/command-injection
 * - Source: Query.defaulted lens
 * - Sink: Runtime.getRuntime().exec()
 *
 * Data Flow: lens with default -> command execution
 *
 * This tests LensBuilder.defaulted$default method
 */
fun commandInjectionEndpoint(request: Request): Response {
    // SOURCE: User input via lens with default value
    val hostLens = Query.defaulted("host", "localhost")
    val host = hostLens(request)

    return try {
        // SINK: Command injection vulnerability
        val process = Runtime.getRuntime().exec(arrayOf("ping", "-c", "1", host))
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()

        Response(Status.OK).body("Exit code: $exitCode\n\nOutput:\n$output")
    } catch (e: Exception) {
        Response(Status.INTERNAL_SERVER_ERROR).body("Error: ${e.message}")
    }
}

/**
 * Alternative command injection with string concatenation
 */
fun alternateCommandInjectionEndpoint(request: Request): Response {
    val command = request.query("cmd") ?: "echo hello"

    // SINK: Command injection via shell
    val process = Runtime.getRuntime().exec("sh -c $command")
    val output = process.inputStream.bufferedReader().readText()

    return Response(Status.OK).body(output)
}