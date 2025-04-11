package com.mlisena.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchange -> exchange
                    .pathMatchers("/realms/**").permitAll()
                    .pathMatchers(
                        "/login/**",
                        "/oauth2/**"
                    ).permitAll()
                    .pathMatchers(
                        "/product-service/swagger-ui.html",
                        "/product-service/swagger-ui/**",
                        "/product-service/v3/api-docs/**"
                    ).permitAll()
                    .pathMatchers(
                        "/booking-service/swagger-ui.html",
                        "/booking-service/swagger-ui/**",
                        "/booking-service/v3/api-docs/**"
                    ).permitAll()
                    .pathMatchers(
                        "/swagger-ui.html",
                        "/swagger-ui/**",
                        "/v3/api-docs",
                        "/v3/api-docs/**"
                    ).permitAll()
                    .pathMatchers(
                        "/api/products/**",
                        "/api/bookings/**"
                    ).authenticated()
                    .anyExchange().permitAll()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                    .jwt(Customizer.withDefaults())
                );

        return http.build();
    }

    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        String issuerUri = "http://keycloak-server:8080/realms/application-realm";
        return ReactiveJwtDecoders.fromIssuerLocation(issuerUri);
    }
}