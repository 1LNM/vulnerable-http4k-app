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
        // V1 routes - Original methods
        "/api/user" bind Method.GET to ::sqlInjectionEndpoint,
        "/api/echo" bind Method.POST to ::xssEndpoint,
        "/api/file" bind Method.GET to ::pathTraversalEndpoint,
        "/api/set-header" bind Method.GET to ::headerInjectionEndpoint,
        "/redirect" bind Method.GET to ::openRedirectEndpoint,
        "/api/ping" bind Method.GET to ::commandInjectionEndpoint,
        "/api/profile" bind Method.GET to ::profileEndpoint,
        "/api/download" bind Method.GET to ::fileDownloadEndpoint,
        "/api/search" bind Method.POST to ::searchEndpoint,
        
        // V2 routes - Testing additional http4k methods
        // SQL Injection V2
        "/api-v2/user-lens-get" bind Method.GET to ::sqlInjectionLensGetEndpoint,
        "/api-v2/user-lens-extract" bind Method.GET to ::sqlInjectionLensExtractEndpoint,
        "/api-v2/user-header" bind Method.GET to ::sqlInjectionRequestHeaderEndpoint,
        "/api-v2/user-uri-query" bind Method.GET to ::sqlInjectionUriQueryEndpoint,
        "/api-v2/user-http-header" bind Method.GET to ::sqlInjectionHttpMessageHeaderEndpoint,
        
        // XSS V2
        "/api-v2/echo-lens-injector" bind Method.GET to ::xssLensInjectorEndpoint,
        "/api-v2/echo-http-body" bind Method.POST to ::xssHttpMessageBodyEndpoint,
        "/api-v2/echo-body-stream" bind Method.POST to ::xssBodyStreamEndpoint,
        "/api-v2/echo-to-message" bind Method.GET to ::xssToMessageEndpoint,
        
        // Path Traversal V2
        "/api-v2/file-uri-path" bind Method.GET to ::pathTraversalUriPathEndpoint,
        "/api-v2/file-uri-getpath" bind Method.GET to ::pathTraversalUriGetPathEndpoint,
        "/api-v2/file-header" bind Method.GET to ::pathTraversalRequestHeaderEndpoint,
        "/api-v2/file-body-stream" bind Method.POST to ::pathTraversalBodyStreamEndpoint,
        
        // Command Injection V2
        "/api-v2/ping-lens-get" bind Method.GET to ::commandInjectionLensGetEndpoint,
        "/api-v2/ping-header" bind Method.GET to ::commandInjectionRequestHeaderEndpoint,
        "/api-v2/ping-http-header" bind Method.GET to ::commandInjectionHttpMessageHeaderEndpoint,
        
        // Header Injection V2
        "/api-v2/set-header-uri-query" bind Method.GET to ::headerInjectionUriQueryEndpoint,
        "/api-v2/set-header-lens-extract" bind Method.GET to ::headerInjectionLensExtractEndpoint,
        "/api-v2/set-header-body-stream" bind Method.POST to ::headerInjectionBodyStreamEndpoint,
        
        // Open Redirect V2
        "/redirect-v2/header" bind Method.GET to ::openRedirectRequestHeaderEndpoint,
        "/redirect-v2/uri-query" bind Method.GET to ::openRedirectUriQueryEndpoint,
        "/redirect-v2/lens-get" bind Method.GET to ::openRedirectLensGetEndpoint
    )

    val server = app.asServer(Netty(8080)).start()

    println("Vulnerable http4k server started on http://localhost:8080")
    println("WARNING: This server contains intentional vulnerabilities for testing!")
    println("\n=== V1 Endpoints (Original Methods) ===")
    println("  GET  /api/user?id=<value>           - SQL Injection")
    println("  POST /api/echo                      - Reflected XSS")
    println("  GET  /api/file?path=<value>         - Path Traversal")
    println("  GET  /api/set-header?value=<value>  - Header Injection")
    println("  GET  /redirect?url=<value>          - Open Redirect")
    println("  GET  /api/ping?host=<value>         - Command Injection")
    println("  GET  /api/profile?username=<value>  - SQL Injection (via lens)")
    println("  GET  /api/download?file=<value>     - Path Traversal (via URI)")
    println("  POST /api/search                    - XSS (via lens extraction)")
    
    println("\n=== V2 Endpoints (Testing New Methods) ===")
    println("SQL Injection V2:")
    println("  GET  /api-v2/user-lens-get?id=<value>          - LensExtractor.get()")
    println("  GET  /api-v2/user-lens-extract?username=<val>  - LensExtractor.extract()")
    println("  GET  /api-v2/user-header                        - Request.header()")
    println("  GET  /api-v2/user-uri-query?id=<value>         - Uri.getQuery()")
    println("  GET  /api-v2/user-http-header                   - HttpMessage.header()")
    
    println("\nXSS V2:")
    println("  GET  /api-v2/echo-lens-injector?msg=<value>    - LensInjector.of()")
    println("  POST /api-v2/echo-http-body                    - HttpMessage.body()")
    println("  POST /api-v2/echo-body-stream                  - Body.getStream()")
    println("  GET  /api-v2/echo-to-message?data=<value>      - Response.toMessage()")
    
    println("\nPath Traversal V2:")
    println("  GET  /api-v2/file-uri-path                     - Uri.path()")
    println("  GET  /api-v2/file-uri-getpath                  - Uri.getPath()")
    println("  GET  /api-v2/file-header                       - Request.header()")
    println("  POST /api-v2/file-body-stream                  - Body.getStream()")
    
    println("\nCommand Injection V2:")
    println("  GET  /api-v2/ping-lens-get?host=<value>       - LensExtractor.get()")
    println("  GET  /api-v2/ping-header                       - Request.header()")
    println("  GET  /api-v2/ping-http-header                  - HttpMessage.header()")
    
    println("\nHeader Injection V2:")
    println("  GET  /api-v2/set-header-uri-query?value=<val> - Uri.getQuery()")
    println("  GET  /api-v2/set-header-lens-extract?header=<> - LensExtractor.extract()")
    println("  POST /api-v2/set-header-body-stream           - Body.getStream()")
    
    println("\nOpen Redirect V2:")
    println("  GET  /redirect-v2/header                       - Request.header()")
    println("  GET  /redirect-v2/uri-query?target=<url>      - Uri.getQuery()")
    println("  GET  /redirect-v2/lens-get?url=<url>          - LensExtractor.get()")
}