package com.watchtower.gateway.auth;

import com.watchtower.gateway.security.JwtTokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Authentication endpoints — login, register, and token refresh.
 * These are public (no JWT required) and handled directly by the gateway.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;

    public AuthController(AuthService authService, JwtTokenProvider jwtTokenProvider,
                          PasswordEncoder passwordEncoder) {
        this.authService = authService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<Map<String, Object>>> login(@RequestBody LoginRequest request) {
        return authService.findByUsername(request.username())
                .filter(user -> passwordEncoder.matches(request.password(), user.passwordHash()))
                .map(user -> {
                    String accessToken = jwtTokenProvider.generateAccessToken(
                            user.id(), user.username(), user.role());
                    String refreshToken = jwtTokenProvider.generateRefreshToken(user.username());

                    return ResponseEntity.ok(Map.<String, Object>of(
                            "accessToken", accessToken,
                            "refreshToken", refreshToken,
                            "username", user.username(),
                            "role", user.role(),
                            "expiresIn", 900  // 15 minutes in seconds
                    ));
                })
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Invalid credentials")));
    }

    @PostMapping("/register")
    public Mono<ResponseEntity<Map<String, Object>>> register(@RequestBody RegisterRequest request) {
        return authService.findByUsername(request.username())
                .flatMap(existing -> Mono.just(ResponseEntity.status(HttpStatus.CONFLICT)
                        .<Map<String, Object>>body(Map.of("error", "Username already exists"))))
                .switchIfEmpty(Mono.defer(() -> {
                    String hashedPassword = passwordEncoder.encode(request.password());
                    return authService.createUser(request.username(), request.email(),
                                    hashedPassword, "ANALYST")
                            .map(user -> {
                                String accessToken = jwtTokenProvider.generateAccessToken(
                                        user.id(), user.username(), user.role());
                                String refreshToken = jwtTokenProvider.generateRefreshToken(user.username());

                                return ResponseEntity.status(HttpStatus.CREATED)
                                        .body(Map.<String, Object>of(
                                                "accessToken", accessToken,
                                                "refreshToken", refreshToken,
                                                "username", user.username(),
                                                "role", user.role()
                                        ));
                            });
                }));
    }

    @PostMapping("/refresh")
    public Mono<ResponseEntity<Map<String, Object>>> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        if (refreshToken == null || !jwtTokenProvider.isTokenValid(refreshToken)) {
            return Mono.just(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid refresh token")));
        }

        String username = jwtTokenProvider.getUsernameFromToken(refreshToken);
        return authService.findByUsername(username)
                .map(user -> {
                    String newAccessToken = jwtTokenProvider.generateAccessToken(
                            user.id(), user.username(), user.role());
                    return ResponseEntity.ok(Map.<String, Object>of(
                            "accessToken", newAccessToken,
                            "expiresIn", 900
                    ));
                })
                .defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "User not found")));
    }

    // ── Request DTOs ──

    public record LoginRequest(String username, String password) {}

    public record RegisterRequest(String username, String email, String password) {}
}
