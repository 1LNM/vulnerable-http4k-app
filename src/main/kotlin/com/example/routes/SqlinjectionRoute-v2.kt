package com.example.routes

import org.http4k.core.*
import org.http4k.lens.*
import java.sql.DriverManager

/**
 * VULNERABILITY: SQL Injection via LensExtractor.get()
 *
 * Expected Detection:
 * - Query: java/sql-injection
 * - Source: LensExtractor.get()
 * - Sink: Statement.executeQuery()
 *
 * Data Flow: LensExtractor.get() -> SQL execution
 *
 * This tests the LensExtractor.get() method as a taint source
 */
fun sqlInjectionLensGetEndpoint(request: Request): Response {
    // SOURCE: User input via LensExtractor.get()
    val userLens = Query.required("id")
    val userId = userLens.get(request)

    val connection = DriverManager.getConnection("jdbc:h2:mem:testdb")
    val statement = connection.createStatement()

    statement.execute("CREATE TABLE IF NOT EXISTS users (id INT, name VARCHAR(255))")
    statement.execute("INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob')")

    // SINK: SQL Injection vulnerability
    val query = "SELECT * FROM users WHERE id = $userId"
    val resultSet = statement.executeQuery(query)

    val results = mutableListOf<String>()
    while (resultSet.next()) {
        results.add("User: ${resultSet.getString("name")}")
    }

    connection.close()

    return Response(Status.OK).body(results.joinToString("\n"))
}

/**
 * VULNERABILITY: SQL Injection via LensExtractor.extract()
 *
 * Expected Detection:
 * - Query: java/sql-injection
 * - Source: LensExtractor.extract()
 * - Sink: Statement.executeQuery()
 *
 * Data Flow: LensExtractor.extract() -> SQL execution
 */
fun sqlInjectionLensExtractEndpoint(request: Request): Response {
    // SOURCE: User input via LensExtractor.extract()
    val usernameLens = Query.required("username")
    val username = usernameLens.extract(request)

    val connection = DriverManager.getConnection("jdbc:h2:mem:testdb")
    val statement = connection.createStatement()

    statement.execute("CREATE TABLE IF NOT EXISTS profiles (username VARCHAR(255), email VARCHAR(255))")
    statement.execute("INSERT INTO profiles VALUES ('admin', 'admin@example.com')")

    // SINK: SQL Injection
    val query = "SELECT * FROM profiles WHERE username = '$username'"
    val resultSet = statement.executeQuery(query)

    val profile = if (resultSet.next()) {
        "Email: ${resultSet.getString("email")}'"
    } else {
        "User not found"
    }

    connection.close()

    return Response(Status.OK).body(profile)
}

/**
 * VULNERABILITY: SQL Injection via Request.header()
 *
 * Expected Detection:
 * - Query: java/sql-injection
 * - Source: Request.header()
 * - Sink: Statement.executeQuery()
 *
 * Data Flow: Request.header() -> SQL execution
 */
fun sqlInjectionRequestHeaderEndpoint(request: Request): Response {
    // SOURCE: User input via Request.header()
    val userId = request.header("X-User-ID") ?: "1"

    val connection = DriverManager.getConnection("jdbc:h2:mem:testdb")
    val statement = connection.createStatement()

    statement.execute("CREATE TABLE IF NOT EXISTS accounts (id INT, balance INT)")
    statement.execute("INSERT INTO accounts VALUES (1, 1000), (2, 2000)")

    // SINK: SQL Injection
    val query = "SELECT * FROM accounts WHERE id = $userId"
    val resultSet = statement.executeQuery(query)

    val account = if (resultSet.next()) {
        "Balance: ${resultSet.getInt("balance")}'"
    } else {
        "Account not found"
    }

    connection.close()

    return Response(Status.OK).body(account)
}

/**
 * VULNERABILITY: SQL Injection via Uri.getQuery()
 *
 * Expected Detection:
 * - Query: java/sql-injection
 * - Source: Uri.getQuery()
 * - Sink: Statement.executeQuery()
 *
 * Data Flow: Request.getUri() -> Uri.getQuery() -> SQL execution
 */
fun sqlInjectionUriQueryEndpoint(request: Request): Response {
    // SOURCE: User input via Uri.getQuery()
    val uri = request.uri
    val queryString = uri.query ?: ""
    
    // Parse the query string manually to extract the id parameter
    val userId = queryString.split("&")
        .find { it.startsWith("id=") }
        ?.substringAfter("id=") ?: "1"

    val connection = DriverManager.getConnection("jdbc:h2:mem:testdb")
    val statement = connection.createStatement()

    statement.execute("CREATE TABLE IF NOT EXISTS orders (id INT, product VARCHAR(255))")
    statement.execute("INSERT INTO orders VALUES (1, 'Laptop'), (2, 'Phone')")

    // SINK: SQL Injection
    val query = "SELECT * FROM orders WHERE id = $userId"
    val resultSet = statement.executeQuery(query)

    val orders = mutableListOf<String>()
    while (resultSet.next()) {
        orders.add("Product: ${resultSet.getString("product")}")
    }

    connection.close()

    return Response(Status.OK).body(orders.joinToString("\n"))
}

/**
 * VULNERABILITY: SQL Injection via HttpMessage.header()
 *
 * Expected Detection:
 * - Query: java/sql-injection
 * - Source: HttpMessage.header()
 * - Sink: Statement.executeQuery()
 *
 * Data Flow: HttpMessage.header() -> SQL execution
 */
fun sqlInjectionHttpMessageHeaderEndpoint(request: Request): Response {
    // SOURCE: User input via HttpMessage.header() (Request extends HttpMessage)
    val apiKey = request.header("X-API-Key") ?: "default"

    val connection = DriverManager.getConnection("jdbc:h2:mem:testdb")
    val statement = connection.createStatement()

    statement.execute("CREATE TABLE IF NOT EXISTS api_keys (key VARCHAR(255), user_id INT)")
    statement.execute("INSERT INTO api_keys VALUES ('abc123', 1), ('def456', 2)")

    // SINK: SQL Injection
    val query = "SELECT user_id FROM api_keys WHERE key = '$apiKey'"
    val resultSet = statement.executeQuery(query)

    val userId = if (resultSet.next()) {
        "User ID: ${resultSet.getInt("user_id")}'"
    } else {
        "Invalid API key"
    }

    connection.close()

    return Response(Status.OK).body(userId)
}
