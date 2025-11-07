package com.example.routes

import org.http4k.core.*
import org.http4k.lens.*

/**
 * VULNERABILITY: Reflected XSS via Response.body()
 *
 * Expected Detection:
 * - Query: java/xss
 * - Source: Body.string().toLens() extraction
 * - Sink: Response.body()
 *
 * Data Flow: request body lens extraction -> response body
 */
fun xssEndpoint(request: Request): Response {
    // SOURCE: Extract user input from request body using lens
    val bodyLens = Body.string(ContentType.TEXT_PLAIN).toLens()
    val userInput = bodyLens.extract(request)

    // SINK: Reflect user input in HTML response without encoding
    val htmlResponse = """
        <html>
            <body>
                <h1>Echo Service</h1>
                <p>You sent: $userInput</p>
            </body>
        </html>
    """.trimIndent()

    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(htmlResponse)
}

/**
 * VULNERABILITY: XSS via Query Parameters and Lens
 *
 * Expected Detection:
 * - Query: java/xss
 * - Source: LensExtractor.extract() or Query lens
 * - Sink: Response.body()
 *
 * Data Flow: query parameter lens -> response body with HTML
 */
fun searchEndpoint(request: Request): Response {
    // SOURCE: Using lens builder with default value
    val searchLens = Query.defaulted("q", "")
    val searchTerm = searchLens(request)

    // SINK: XSS in response body
    val htmlResponse = """
        <html>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: $searchTerm</p>
                <p>No results found.</p>
            </body>
        </html>
    """.trimIndent()

    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(htmlResponse)
}