package com.watchtower.gateway.auth;

import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * User management service — reactive R2DBC queries against gateway_db.
 */
@Service
public class AuthService {

    private final DatabaseClient databaseClient;

    public AuthService(DatabaseClient databaseClient) {
        this.databaseClient = databaseClient;
    }

    public Mono<UserRecord> findByUsername(String username) {
        return databaseClient.sql("SELECT id, username, email, password_hash, role, enabled FROM users WHERE username = :username")
                .bind("username", username)
                .map(row -> new UserRecord(
                        row.get("id", Long.class),
                        row.get("username", String.class),
                        row.get("email", String.class),
                        row.get("password_hash", String.class),
                        row.get("role", String.class),
                        row.get("enabled", Boolean.class)
                ))
                .first();
    }

    public Mono<UserRecord> createUser(String username, String email, String passwordHash, String role) {
        return databaseClient.sql("""
                        INSERT INTO users (username, email, password_hash, role)
                        VALUES (:username, :email, :passwordHash, :role)
                        RETURNING id, username, email, password_hash, role, enabled
                        """)
                .bind("username", username)
                .bind("email", email)
                .bind("passwordHash", passwordHash)
                .bind("role", role)
                .map(row -> new UserRecord(
                        row.get("id", Long.class),
                        row.get("username", String.class),
                        row.get("email", String.class),
                        row.get("password_hash", String.class),
                        row.get("role", String.class),
                        row.get("enabled", Boolean.class)
                ))
                .first();
    }

    public record UserRecord(Long id, String username, String email,
                              String passwordHash, String role, Boolean enabled) {}
}
