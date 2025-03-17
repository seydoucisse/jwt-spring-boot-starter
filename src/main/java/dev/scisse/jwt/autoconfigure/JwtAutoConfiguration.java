/*
 * Copyright (C) 2025 seydoucisse.github.io
 *
 * Licensed under the MIT License (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/MIT
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package dev.scisse.jwt.autoconfigure;

import dev.scisse.jwt.config.JwtProperties;
import dev.scisse.jwt.filter.JwtAuthenticationFilter;
import dev.scisse.jwt.service.JwtTokenService;
import dev.scisse.jwt.service.TokenBlacklistService;
import dev.scisse.jwt.service.impl.JwtTokenServiceImpl;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Objects;

/**
 * Autoconfiguration for JWT authentication.
 * <p>
 * This class automatically configures JWT components when the starter is
 * included in a Spring Boot application. It provides the necessary beans for
 * JWT authentication, including:
 * <ul>
 *   <li>JwtTokenService - for token generation, validation, and management</li>
 *   <li>JwtAuthenticationFilter - for processing JWT tokens in HTTP requests</li>
 *   <li>SecurityFilterChain - for configuring Spring Security with JWT support</li>
 * </ul>
 *
 * <p>
 * The autoconfiguration is conditionally applied based on:
 * <ul>
 *   <li>The presence of JwtTokenService class in the classpath</li>
 *   <li>The 'jwt.enabled' property (defaults to true if not specified)</li>
 *   <li>Whether the application is a web application</li>
 * </ul>
 *
 * <p>
 * Required properties:
 * <ul>
 *   <li>jwt.secret - The secret key used for signing JWT tokens</li>
 *   <li>jwt.issuer - The issuer claim to include in JWT tokens</li>
 * </ul>
 *
 * 
 * @author Seydou CISSE
 * @since 0.1.0
 * @see dev.scisse.jwt.config.JwtProperties
 * @see dev.scisse.jwt.service.JwtTokenService
 * @see dev.scisse.jwt.filter.JwtAuthenticationFilter
 */
@Configuration
@EnableConfigurationProperties(JwtProperties.class)
@ConditionalOnClass(JwtTokenService.class)
@EnableScheduling
public class JwtAutoConfiguration {

    /**
     * Creates a JwtTokenService bean if one doesn't exist.
     * <p>
     * This method creates and configures a JwtTokenServiceImpl instance
     * using the provided JWT properties and token blacklist service.
     * 
     * <p>
     * The method validates that the required properties are set:
     * <ul>
     *   <li>jwt.secret - Must be non-null and non-empty</li>
     *   <li>jwt.issuer - Must be non-null and non-empty</li>
     * </ul>
     * If these properties are not set, an IllegalArgumentException is thrown.
     *
     * <p>
     * This bean is only created if no other JwtTokenService bean exists in the
     * application context, allowing applications to provide their own implementation
     * if needed.
     *
     *
     * @param jwtProperties JWT configuration properties
     * @param tokenBlacklistService Token blacklist service for invalidating tokens
     * @return JwtTokenService implementation
     * @throws IllegalArgumentException if required properties are missing
     * @see dev.scisse.jwt.service.impl.JwtTokenServiceImpl
     * @see dev.scisse.jwt.config.JwtProperties
     * @see dev.scisse.jwt.service.TokenBlacklistService
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtTokenService jwtTokenService(JwtProperties jwtProperties, TokenBlacklistService tokenBlacklistService) {
        if (Objects.isNull(jwtProperties.getSecret()) || jwtProperties.getSecret().trim().isEmpty()) {
            throw new IllegalArgumentException("JWT secret is required. Please set 'jwt.secret' in your application properties.");
        }

        if (Objects.isNull(jwtProperties.getIssuer()) || jwtProperties.getIssuer().trim().isEmpty()) {
            throw new IllegalArgumentException("JWT issuer is required. Please set 'jwt.issuer' in your application properties.");
        }

        return new JwtTokenServiceImpl(jwtProperties, tokenBlacklistService);
    }

    /**
     * Creates a JwtAuthenticationFilter bean if JWT authentication is enabled.
     * <p>
     * This filter intercepts HTTP requests and extracts JWT tokens from request headers.
     * It validates the tokens and sets up the Spring Security authentication context
     * based on the token's claims.
     *
     * <p>
     * This bean is conditionally created based on:
     * <ul>
     *   <li>The 'jwt.enabled' property being true (default is true)</li>
     *   <li>The application being a web application</li>
     * </ul>
     *
     *
     * @param jwtTokenService JWT token service for validating tokens
     * @param jwtProperties JWT configuration properties
     * @param userDetailsService Service to load user details by username
     * @return JwtAuthenticationFilter instance
     * @see dev.scisse.jwt.filter.JwtAuthenticationFilter
     * @see dev.scisse.jwt.service.JwtTokenService
     * @see dev.scisse.jwt.config.JwtProperties
     */
    @Bean
    @ConditionalOnProperty(name = "jwt.enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnWebApplication
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            JwtTokenService jwtTokenService,
            JwtProperties jwtProperties,
            UserDetailsService userDetailsService) {
        return new JwtAuthenticationFilter(jwtTokenService, jwtProperties, userDetailsService);
    }

    /**
     * Configures Spring Security to use JWT authentication if Spring Security is present.
     * <p>
     * This method creates a default SecurityFilterChain that:
     * <ul>
     *   <li>Enables CORS with default settings</li>
     *   <li>Disables CSRF protection (as JWT is stateless)</li>
     *   <li>Sets up stateless session management</li>
     *   <li>Adds the JWT authentication filter before the UsernamePasswordAuthenticationFilter</li>
     * </ul>
     *
     * <p>
     * This configuration is optional and will only be applied if:
     * <ul>
     *   <li>Spring Security is in the classpath</li>
     *   <li>JWT is enabled (via the 'jwt.enabled' property, default is true)</li>
     *   <li>The application is a web application</li>
     *   <li>No other SecurityFilterChain bean exists in the application context</li>
     * </ul>
     * This allows applications to provide their own security configuration if needed.
     *
     *
     * @param http HttpSecurity to configure
     * @param jwtAuthenticationFilter JWT authentication filter
     * @return Configured SecurityFilterChain
     * @throws Exception if configuration fails
     * @see org.springframework.security.web.SecurityFilterChain
     * @see dev.scisse.jwt.filter.JwtAuthenticationFilter
     */
    @Bean
    @ConditionalOnClass(name = "org.springframework.security.config.annotation.web.builders.HttpSecurity")
    @ConditionalOnProperty(name = "jwt.enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnWebApplication
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter) throws Exception {
        return http
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}