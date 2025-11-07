package com.example.routes

import org.http4k.core.*

/**
 * VULNERABILITY: Open Redirect via Response.create() with Status redirect
 *
 * Expected Detection:
 * - Query: java/unvalidated-url-redirection
 * - Source: Request.query("url")
 * - Sink: Response with redirect status (Status.FOUND, etc.)
 *
 * Data Flow: query parameter -> redirect location
 *
 * Note: This tests Response.create$default and Status companion object
 */
fun openRedirectEndpoint(request: Request): Response {
    // SOURCE: User-controlled redirect URL
    val redirectUrl = request.query("url") ?: "https://example.com"

    // SINK: Open redirect vulnerability
    // Using Response companion create with Status companion
    return Response(Status.FOUND)
        .header("Location", redirectUrl)
}

/**
 * Alternative open redirect using different response construction
 */
fun alternateRedirectEndpoint(request: Request): Response {
    val targetUrl = request.query("target") ?: "/"

    // Using Status companion getters
    val redirectStatus = Status.MOVED_PERMANENTLY

    return Response(redirectStatus)
        .header("Location", targetUrl)
        .body("Redirecting to $targetUrl")
}