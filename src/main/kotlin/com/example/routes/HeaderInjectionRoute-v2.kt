package com.example.routes

import org.http4k.core.*
import org.http4k.lens.*

/**
 * VULNERABILITY: Header Injection via Uri.getQuery()
 *
 * Expected Detection:
 * - Query: java/http-response-splitting
 * - Source: Uri.getQuery()
 * - Sink: Response.header()
 *
 * Data Flow: Uri.getQuery() -> parse query -> Response.header()
 */
fun headerInjectionUriQueryEndpoint(request: Request): Response {
    // SOURCE: User input via Uri.getQuery()
    val uri = request.uri
    val queryString = uri.query ?: ""
    
    // Parse the query string manually to extract the value parameter
    val headerValue = queryString.split("&")
        .find { it.startsWith("value=") }
        ?.substringAfter("value=") ?: "default"

    // SINK: Header injection vulnerability
    return Response(Status.OK)
        .header("X-Custom-Header", headerValue)
        .body("Header set successfully")
}

/**
 * VULNERABILITY: Header Injection via LensExtractor.extract()
 *
 * Expected Detection:
 * - Query: java/http-response-splitting
 * - Source: LensExtractor.extract()
 * - Sink: Response.header()
 *
 * Data Flow: LensExtractor.extract() -> Response.header()
 */
fun headerInjectionLensExtractEndpoint(request: Request): Response {
    // SOURCE: User input via LensExtractor.extract()
    val headerLens = Query.required("header")
    val headerValue = headerLens.extract(request)

    // SINK: Header injection vulnerability
    return Response(Status.OK)
        .header("X-User-Controlled", headerValue)
        .body("Custom header set")
}

/**
 * VULNERABILITY: Header Injection via Body.getStream()
 *
 * Expected Detection:
 * - Query: java/http-response-splitting
 * - Source: Body.getStream()
 * - Sink: Response.header()
 *
 * Data Flow: Body.getStream() -> read value -> Response.header()
 */
fun headerInjectionBodyStreamEndpoint(request: Request): Response {
    // SOURCE: User input via Body.getStream()
    val stream = request.body.stream
    val headerValue = stream.reader().readText().trim()

    // SINK: Header injection vulnerability
    return Response(Status.OK)
        .header("X-Dynamic-Header", headerValue)
        .body("Header injected from body stream")
}