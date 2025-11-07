package com.example.routes

import org.http4k.core.*
import java.io.File

/**
 * VULNERABILITY: Path Traversal via Request.query()
 *
 * Expected Detection:
 * - Query: java/path-injection
 * - Source: Request.query("path")
 * - Sink: File() constructor / File.readText()
 *
 * Data Flow: query parameter -> file system access
 */
fun pathTraversalEndpoint(request: Request): Response {
    // SOURCE: User-controlled path parameter
    val filePath = request.query("path") ?: "default.txt"

    // SINK: Path traversal vulnerability - unsanitized path
    val file = File("/var/www/html/$filePath")

    return try {
        val content = file.readText()
        Response(Status.OK).body(content)
    } catch (e: Exception) {
        Response(Status.NOT_FOUND).body("File not found: ${e.message}")
    }
}

/**
 * VULNERABILITY: Path Traversal via Uri.of()
 *
 * Expected Detection:
 * - Query: java/path-injection
 * - Source: Request.query("file")
 * - Summary: Uri.of() should propagate taint
 * - Sink: File() constructor
 *
 * Data Flow: query parameter -> Uri.of() -> file path -> file access
 */
fun fileDownloadEndpoint(request: Request): Response {
    // SOURCE: User input
    val fileName = request.query("file") ?: "index.html"

    // SUMMARY: Uri.of should propagate taint
    val uri = Uri.of(fileName)

    // SINK: Path traversal via URI path
    val file = File("/downloads/${uri.path}")

    return try {
        val content = file.readBytes()
        Response(Status.OK)
            .header("Content-Disposition", "attachment; filename=${uri.path}")
            .body(content.inputStream())
    } catch (e: Exception) {
        Response(Status.NOT_FOUND).body("File not found")
    }
}