package com.example.routes

import org.http4k.core.*

/**
 * VULNERABILITY: HTTP Header Injection via Response.header()
 *
 * Expected Detection:
 * - Query: java/http-response-splitting
 * - Source: Request.query("value")
 * - Sink: Response.header()
 *
 * Data Flow: query parameter -> HTTP header value
 *
 * Attack: User could inject newlines to add arbitrary headers or split response
 * Example: ?value=test%0d%0aX-Injected-Header:%20malicious
 */
fun headerInjectionEndpoint(request: Request): Response {
    // SOURCE: User-controlled input
    val headerValue = request.query("value") ?: "default"

    // SINK: Header injection vulnerability
    return Response(Status.OK)
        .header("X-Custom-Header", headerValue)
        .body("Header set successfully")
}