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
        "/api/user" bind Method.GET to ::sqlInjectionEndpoint,
        "/api/echo" bind Method.POST to ::xssEndpoint,
        "/api/file" bind Method.GET to ::pathTraversalEndpoint,
        "/api/set-header" bind Method.GET to ::headerInjectionEndpoint,
        "/redirect" bind Method.GET to ::openRedirectEndpoint,
        "/api/ping" bind Method.GET to ::commandInjectionEndpoint,
        "/api/profile" bind Method.GET to ::profileEndpoint,
        "/api/download" bind Method.GET to ::fileDownloadEndpoint,
        "/api/search" bind Method.POST to ::searchEndpoint
    )

    val server = app.asServer(Netty(8080)).start()

    println("Vulnerable http4k server started on http://localhost:8080")
    println("WARNING: This server contains intentional vulnerabilities for testing!")
    println("\nAvailable endpoints:")
    println("  GET  /api/user?id=<value>           - SQL Injection")
    println("  POST /api/echo                      - Reflected XSS")
    println("  GET  /api/file?path=<value>         - Path Traversal")
    println("  GET  /api/set-header?value=<value>  - Header Injection")
    println("  GET  /redirect?url=<value>          - Open Redirect")
    println("  GET  /api/ping?host=<value>         - Command Injection")
    println("  GET  /api/profile?id=<value>        - SQL Injection (via lens)")
    println("  GET  /api/download?file=<value>     - Path Traversal (via URI)")
    println("  POST /api/search                    - XSS (via lens extraction)")
}