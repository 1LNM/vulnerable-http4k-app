package com.example.routes

import org.http4k.core.*
import org.http4k.lens.Query
import java.sql.DriverManager

/**
 * VULNERABILITY: SQL Injection via Request.query()
 *
 * Expected Detection:
 * - Query: java/sql-injection
 * - Source: Request.query("id")
 * - Sink: Statement.executeQuery()
 *
 * Data Flow: request.query("id") -> string concatenation -> SQL execution
 */
fun sqlInjectionEndpoint(request: Request): Response {
    // SOURCE: User-controlled query parameter
    val userId = request.query("id") ?: "1"

    // Initialize H2 in-memory database
    val connection = DriverManager.getConnection("jdbc:h2:mem:testdb")
    val statement = connection.createStatement()

    // Create sample table
    statement.execute("CREATE TABLE IF NOT EXISTS users (id INT, name VARCHAR(255))")
    statement.execute("INSERT INTO users VALUES (1, 'Alice'), (2, 'Bob')")

    // SINK: SQL Injection vulnerability - unsanitized user input in query
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
 * VULNERABILITY: SQL Injection via Lens
 *
 * Expected Detection:
 * - Query: java/sql-injection
 * - Source: Query.required("username") lens extraction
 * - Sink: Statement.executeQuery()
 *
 * Data Flow: lens extraction -> SQL execution
 */
fun profileEndpoint(request: Request): Response {
    // SOURCE: User input via lens
    //val userId = Query.required("id")(request)
    val userId = request.query("id") ?: "1"

    // Initialize H2 in-memory database
    val connection = DriverManager.getConnection("jdbc:h2:mem:testdb")
    val statement = connection.createStatement()

    // Create sample table
    statement.execute("CREATE TABLE IF NOT EXISTS profiles (id INT, email VARCHAR(255))")
    statement.execute("INSERT INTO profiles VALUES (1, 'admin@example.com'), (2, 'user@example.com')")

    // SINK: SQL Injection vulnerability - unsanitized user input in query
    val query = "SELECT * FROM profiles WHERE id = $userId"
    val resultSet = statement.executeQuery(query)

    val results = mutableListOf<String>()
    while (resultSet.next()) {
        results.add("Email: ${resultSet.getString("email")}")
    }

    connection.close()

    return Response(Status.OK).body(results.joinToString("\n"))
}