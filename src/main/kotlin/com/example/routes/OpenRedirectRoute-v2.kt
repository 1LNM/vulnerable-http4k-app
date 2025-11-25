package com.example.routes

import org.http4k.core.*
import org.http4k.lens.*

/**
 * VULNERABILITY: Open Redirect via Request.header()
 *
 * Expected Detection:
 * - Query: java/unvalidated-url-redirection
 * - Source: Request.header()
 * - Sink: Response with redirect status
 *
 * Data Flow: Request.header() -> redirect location
 */
fun openRedirectRequestHeaderEndpoint(request: Request): Response {
    // SOURCE: User-controlled redirect URL from header
    val redirectUrl = request.header("X-Redirect-To") ?: "https://example.com"

    // SINK: Open redirect vulnerability
    return Response(Status.FOUND)
        .header("Location", redirectUrl)
}

/**
 * VULNERABILITY: Open Redirect via Uri.getQuery()
 *
 * Expected Detection:
 * - Query: java/unvalidated-url-redirection
 * - Source: Uri.getQuery()
 * - Sink: Response with redirect status
 *
 * Data Flow: Uri.getQuery() -> parse query -> redirect location
 */
fun openRedirectUriQueryEndpoint(request: Request): Response {
    // SOURCE: User input via Uri.getQuery()
    val uri = request.uri
    val queryString = uri.query ?: ""
    
    // Parse the query string manually to extract the target parameter
    val targetUrl = queryString.split("&")
        .find { it.startsWith("target=") }
        ?.substringAfter("target=") ?: "/"

    // SINK: Open redirect vulnerability
    return Response(Status.MOVED_PERMANENTLY)
        .header("Location", targetUrl)
        .body("Redirecting to $targetUrl")
}

/**
 * VULNERABILITY: Open Redirect via LensExtractor.get()
 *
 * Expected Detection:
 * - Query: java/unvalidated-url-redirection
 * - Source: LensExtractor.get()
 * - Sink: Response with redirect status
 *
 * Data Flow: LensExtractor.get() -> redirect location
 */
fun openRedirectLensGetEndpoint(request: Request): Response {
    // SOURCE: User input via LensExtractor.get()
    val urlLens = Query.required("url")
    val redirectUrl = urlLens.get(request)

    // SINK: Open redirect vulnerability
    return Response(Status.TEMPORARY_REDIRECT)
        .header("Location", redirectUrl)
        .body("Redirecting...")
}