package com.example.routes

import org.http4k.core.*
import org.http4k.lens.*
import java.io.File

/**
 * VULNERABILITY: Path Traversal via Request.getUri() and Uri.path()
 *
 * Expected Detection:
 * - Query: java/path-injection
 * - Source: Request.getUri() -> Uri.path()
 * - Sink: File() constructor
 *
 * Data Flow: Request.getUri() -> Uri.path() -> file system access
 */
fun pathTraversalUriPathEndpoint(request: Request): Response {
    // SOURCE: User input via Request.getUri() and Uri.path()
    val uri = request.uri
    val filePath = uri.path

    // SINK: Path traversal vulnerability
    val file = File("/var/www/html$filePath")

    return try {
        val content = file.readText()
        Response(Status.OK).body(content)
    } catch (e: Exception) {
        Response(Status.NOT_FOUND).body("File not found: ${'$'}{e.message}")
    }
}

/**
 * VULNERABILITY: Path Traversal via Uri.getPath()
 *
 * Expected Detection:
 * - Query: java/path-injection
 * - Source: Request.uri -> Uri.getPath()
 * - Sink: File() constructor
 *
 * Data Flow: Uri.getPath() -> file system access
 */
fun pathTraversalUriGetPathEndpoint(request: Request): Response {
    // SOURCE: User input via Uri.getPath()
    val uri = request.uri
    val filePath = uri.path  // Using .path property which calls getPath()

    // SINK: Path traversal via Uri.getPath()
    val file = File("/downloads$filePath")

    return try {
        val content = file.readBytes()
        Response(Status.OK)
            .header("Content-Disposition", "attachment; filename=${filePath.substringAfterLast("/")}")
            .body(content.inputStream())
    } catch (e: Exception) {
        Response(Status.NOT_FOUND).body("File not found")
    }
}

/**
 * VULNERABILITY: Path Traversal via Request.header()
 *
 * Expected Detection:
 * - Query: java/path-injection
 * - Source: Request.header()
 * - Sink: File() constructor
 *
 * Data Flow: Request.header() -> file path construction -> file access
 */
fun pathTraversalRequestHeaderEndpoint(request: Request): Response {
    // SOURCE: User input via Request.header() - filename from header
    val filename = request.header("X-Filename") ?: "default.txt"

    // SINK: Path traversal vulnerability
    val file = File("/uploads/$filename")

    return try {
        val content = file.readText()
        Response(Status.OK).body(content)
    } catch (e: Exception) {
        Response(Status.NOT_FOUND).body("File not found: ${'$'}{e.message}")
    }
}

/**
 * VULNERABILITY: Path Traversal via Body.getStream()
 *
 * Expected Detection:
 * - Query: java/path-injection
 * - Source: Body.getStream()
 * - Sink: File() constructor
 *
 * Data Flow: Body.getStream() -> read filename -> file access
 */
fun pathTraversalBodyStreamEndpoint(request: Request): Response {
    // SOURCE: User input via Body.getStream()
    val stream = request.body.stream
    val filename = stream.reader().readText().trim()

    // SINK: Path traversal vulnerability
    val file = File("/data/$filename")

    return try {
        val content = file.readText()
        Response(Status.OK).body("File content: $content")
    } catch (e: Exception) {
        Response(Status.NOT_FOUND).body("File not found: ${'$'}{e.message}")
    }
}