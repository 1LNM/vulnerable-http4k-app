package com.example.routes

import org.http4k.core.*
import org.http4k.lens.*

/**
 * VULNERABILITY: XSS via LensInjector.of()
 *
 * Expected Detection:
 * - Query: java/xss
 * - Source: Request.query()
 * - Sink: LensInjector.of() -> Response body
 *
 * Data Flow: query parameter -> LensInjector.of() -> HTML response
 *
 * This tests LensInjector.of() as a taint propagator/sink
 */
fun xssLensInjectorEndpoint(request: Request): Response {
    // SOURCE: User input
    val message = request.query("msg") ?: "Hello"

    // SINK: LensInjector.of() injects tainted data into response
    val htmlBody = """
        <html>
            <body>
                <h1>Message Board</h1>
                <p>
                    $message
                </p>
            </body>
        </html>
    """.trimIndent()

    val bodyLens = Body.string(ContentType.TEXT_HTML).toLens()
    
    return bodyLens.inject(htmlBody, Response(Status.OK))
}

/**
 * VULNERABILITY: XSS via HttpMessage.body()
 *
 * Expected Detection:
 * - Query: java/xss
 * - Source: HttpMessage.body() (reading request body)
 * - Sink: Response.body()
 *
 * Data Flow: HttpMessage.body() -> Response.body() with HTML
 */
fun xssHttpMessageBodyEndpoint(request: Request): Response {
    // SOURCE: User input via HttpMessage.body()
    val bodyContent = request.body.toString()

    // SINK: Reflect in HTML response
    val htmlResponse = """
        <html>
            <body>
                <h1>Body Echo</h1>
                <div>
                    $bodyContent
                </div>
            </body>
        </html>
    """.trimIndent()

    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(htmlResponse)
}

/**
 * VULNERABILITY: XSS via Body.getStream()
 *
 * Expected Detection:
 * - Query: java/xss
 * - Source: Body.getStream()
 * - Sink: Response.body()
 *
 * Data Flow: Body.getStream() -> read content -> HTML response
 */
fun xssBodyStreamEndpoint(request: Request): Response {
    // SOURCE: User input via Body.getStream()
    val stream = request.body.stream
    val userContent = stream.reader().readText()

    // SINK: XSS in HTML response
    val htmlResponse = """
        <html>
            <body>
                <h1>Stream Echo</h1>
                <pre>
                    $userContent
                </pre>
            </body>
        </html>
    """.trimIndent()

    return Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(htmlResponse)
}

/**
 * VULNERABILITY: XSS via Response.toMessage()
 *
 * Expected Detection:
 * - Query: java/xss
 * - Source: Request.query()
 * - Sink: Response.toMessage()
 *
 * Data Flow: query parameter -> Response construction -> toMessage()
 *
 * This tests Response.toMessage() as a sink
 */
fun xssToMessageEndpoint(request: Request): Response {
    // SOURCE: User input
    val data = request.query("data") ?: ""

    // Create response with user data
    val htmlContent = """
        <html>
            <body>
                <h1>Data Display</h1>
                <p>
                    Data: $data
                </p>
            </body>
        </html>
    """.trimIndent()

    val response = Response(Status.OK)
        .header("Content-Type", "text/html")
        .body(htmlContent)

    // SINK: Call Response.toMessage() for taint/sink analysis (side effect)
    response.toMessage()

    return response
}