package com.example

import org.http4k.core.*
import org.http4k.server.Netty
import org.http4k.server.asServer
import org.http4k.routing.routes
import org.http4k.routing.bind
import com.example.routes.*

/**
 * Main application - Intentionally Vulnerable http4k Application
 *
 * Purpose: Test CodeQL models for http4k library
 *
 * This application contains INTENTIONAL security vulnerabilities for testing purposes.
 * DO NOT use this code in production!
 */
fun main() {
    val app = routes(
        // v1 endpoints
        "/api/user" bind Method.GET to ::sqlInjectionEndpoint,
        "/api/echo" bind Method.POST to ::xssEndpoint,
        "/api/file" bind Method.GET to ::pathTraversalEndpoint,
        "/api/set-header" bind Method.GET to ::headerInjectionEndpoint,
        "/redirect" bind Method.GET to ::openRedirectEndpoint,
        "/api/ping" bind Method.GET to ::commandInjectionEndpoint,
        "/api/profile" bind Method.GET to ::profileEndpoint,
        "/api/download" bind Method.GET to ::fileDownloadEndpoint,
        "/api/search" bind Method.POST to ::searchEndpoint,

        // v2 endpoints - SQL Injection
        "/api/v2/sql/lens-get" bind Method.GET to ::sqlInjectionLensGetEndpoint,
        "/api/v2/sql/lens-extract" bind Method.GET to ::sqlInjectionLensExtractEndpoint,
        "/api/v2/sql/request-header" bind Method.GET to ::sqlInjectionRequestHeaderEndpoint,
        "/api/v2/sql/uri-query" bind Method.GET to ::sqlInjectionUriQueryEndpoint,
        "/api/v2/sql/httpmessage-header" bind Method.GET to ::sqlInjectionHttpMessageHeaderEndpoint,

        // v2 endpoints - XSS
        "/api/v2/xss/lens-injector" bind Method.GET to ::xssLensInjectorEndpoint,
        "/api/v2/xss/httpmessage-body" bind Method.POST to ::xssHttpMessageBodyEndpoint,
        "/api/v2/xss/body-stream" bind Method.POST to ::xssBodyStreamEndpoint,
        "/api/v2/xss/to-message" bind Method.GET to ::xssToMessageEndpoint,

        // v2 endpoints - Path Traversal
        "/api/v2/path/uri-path" bind Method.GET to ::pathTraversalUriPathEndpoint,
        "/api/v2/path/uri-getpath" bind Method.GET to ::pathTraversalUriGetPathEndpoint,
        "/api/v2/path/request-header" bind Method.GET to ::pathTraversalRequestHeaderEndpoint,
        "/api/v2/path/body-stream" bind Method.POST to ::pathTraversalBodyStreamEndpoint,

        // v2 endpoints - Header Injection
        "/api/v2/header/uri-query" bind Method.GET to ::headerInjectionUriQueryEndpoint,
        "/api/v2/header/lens-extract" bind Method.GET to ::headerInjectionLensExtractEndpoint,
        "/api/v2/header/body-stream" bind Method.POST to ::headerInjectionBodyStreamEndpoint,

        // v2 endpoints - Open Redirect
        "/api/v2/redirect/request-header" bind Method.GET to ::openRedirectRequestHeaderEndpoint,
        "/api/v2/redirect/uri-query" bind Method.GET to ::openRedirectUriQueryEndpoint,
        "/api/v2/redirect/lens-get" bind Method.GET to ::openRedirectLensGetEndpoint,

        // v2 endpoints - Command Injection
        "/api/v2/cmd/lens-get" bind Method.GET to ::commandInjectionLensGetEndpoint,
        "/api/v2/cmd/request-header" bind Method.GET to ::commandInjectionRequestHeaderEndpoint,
        "/api/v2/cmd/httpmessage-header" bind Method.GET to ::commandInjectionHttpMessageHeaderEndpoint
    )

    val server = app.asServer(Netty(8080)).start()

    println("Vulnerable http4k server started on http://localhost:8080")
    println("WARNING: This server contains intentional vulnerabilities for testing!")
    println("\nAvailable endpoints:")
    println("\n=== v1 Endpoints ===")
    println("  GET  /api/user?id=<value>           - SQL Injection")
    println("  POST /api/echo                      - Reflected XSS")
    println("  GET  /api/file?path=<value>         - Path Traversal")
    println("  GET  /api/set-header?value=<value>  - Header Injection")
    println("  GET  /redirect?url=<value>          - Open Redirect")
    println("  GET  /api/ping?host=<value>         - Command Injection")
    println("  GET  /api/profile?username=<value>  - SQL Injection (via lens)")
    println("  GET  /api/download?file=<value>     - Path Traversal (via URI)")
    println("  POST /api/search                    - XSS (via lens extraction)")

    println("\n=== V2 Endpoints - SQL Injection ===")
    println("  GET  /api/v2/sql/lens-get?id=<value>              - SQL Injection via LensExtractor.get()")
    println("  GET  /api/v2/sql/lens-extract?username=<value>    - SQL Injection via LensExtractor.extract()")
    println("  GET  /api/v2/sql/request-header                   - SQL Injection via Request.header() [X-User-ID]")
    println("  GET  /api/v2/sql/uri-query?id=<value>             - SQL Injection via Uri.getQuery()")
    println("  GET  /api/v2/sql/httpmessage-header               - SQL Injection via HttpMessage.header() [X-API-Key]")

    println("\n=== V2 Endpoints - XSS ===")
    println("  GET  /api/v2/xss/lens-injector?msg=<value>        - XSS via LensInjector.of()")
    println("  POST /api/v2/xss/httpmessage-body                 - XSS via HttpMessage.body()")
    println("  POST /api/v2/xss/body-stream                      - XSS via Body.getStream()")
    println("  GET  /api/v2/xss/to-message?data=<value>          - XSS via Response.toMessage()")

    println("\n=== V2 Endpoints - Path Traversal ===")
    println("  GET  /api/v2/path/uri-path                        - Path Traversal via Request.getUri() and Uri.path()")
    println("  GET  /api/v2/path/uri-getpath                     - Path Traversal via Uri.getPath()")
    println("  GET  /api/v2/path/request-header                  - Path Traversal via Request.header() [X-Filename]")
    println("  POST /api/v2/path/body-stream                     - Path Traversal via Body.getStream()")

    println("\n=== V2 Endpoints - Header Injection ===")
    println("  GET  /api/v2/header/uri-query?value=<value>       - Header Injection via Uri.getQuery()")
    println("  GET  /api/v2/header/lens-extract?header=<value>   - Header Injection via LensExtractor.extract()")
    println("  POST /api/v2/header/body-stream                   - Header Injection via Body.getStream()")

    println("\n=== V2 Endpoints - Open Redirect ===")
    println("  GET  /api/v2/redirect/request-header              - Open Redirect via Request.header() [X-Redirect-To]")
    println("  GET  /api/v2/redirect/uri-query?target=<value>    - Open Redirect via Uri.getQuery()")
    println("  GET  /api/v2/redirect/lens-get?url=<value>        - Open Redirect via LensExtractor.get()")

    println("\n=== V2 Endpoints - Command Injection ===")
    println("  GET  /api/v2/cmd/lens-get?host=<value>            - Command Injection via LensExtractor.get()")
    println("  GET  /api/v2/cmd/request-header                   - Command Injection via Request.header() [X-Command]")
    println("  GET  /api/v2/cmd/httpmessage-header               - Command Injection via HttpMessage.header() [X-Target]")
}