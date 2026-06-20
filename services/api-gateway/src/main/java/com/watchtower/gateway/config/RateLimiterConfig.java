package com.watchtower.gateway.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

/**
 * Rate limiter key resolver — uses the authenticated user's IP address
 * (or "anonymous" if not present) as the rate limiting key.
 */
@Configuration
public class RateLimiterConfig {

    @Bean
    public KeyResolver userKeyResolver() {
        return exchange -> {
            String userId = exchange.getRequest().getHeaders().getFirst("X-User-Id");
            if (userId != null) {
                return Mono.just(userId);
            }
            // Fall back to client IP for unauthenticated requests
            if (exchange.getRequest().getRemoteAddress() != null) {
                java.net.InetAddress address = exchange.getRequest().getRemoteAddress().getAddress();
                if (address != null) {
                    return Mono.just(address.getHostAddress());
                } else {
                    return Mono.just(exchange.getRequest().getRemoteAddress().getHostString());
                }
            }
            return Mono.just("anonymous");
        };
    }
}
