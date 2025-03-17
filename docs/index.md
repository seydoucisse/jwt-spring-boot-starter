---
layout: default
title: JWT Spring Boot Starter
---

# JWT Spring Boot Starter

A Spring Boot starter for JWT authentication that simplifies the implementation of JWT-based authentication in your Spring Boot applications.

## Features

- Easy integration with Spring Security
- Configurable JWT token generation and validation
- Support for custom claims and token expiration
- Automatic token refresh mechanism
- Customizable authentication endpoints
- Token blacklisting for invalidation
- In-memory token blacklist implementation (with option to provide your own)

## Getting Started

### Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>io.github.seydoucisse</groupId>
    <artifactId>jwt-spring-boot-starter</artifactId>
    <version>0.1.0</version>
</dependency>
```

### Configuration

1. Add required properties in `application.properties` or `application.yml`:
   - `jwt.secret`: Your JWT signing key
   - `jwt.issuer`: Your application name

```yaml
jwt:
  secret: your_secret_key
  issuer: your-app-issuer
```

2. Implement `UserDetailsService`:
   - Create a service class that implements `UserDetailsService`
   - Override `loadUserByUsername()` method
   - Connect to your user data source

```java
@Service
public class MyUserDetailsService implements UserDetailsService {
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // Load user from your database or other source
        // Return a UserDetails implementation
        // Throw UsernameNotFoundException if user not found
    }
}
```

3. Optional: Customize the configuration
   - Override default JWT properties
   - Implement custom security configuration
   - Add custom token blacklist service

For detailed configuration options, see the [Configuration Properties](#configuration-properties) section below. For customization options, see the [Advanced Usage](#advanced-Usage) section.

## Configuration Properties

The starter can be configured with the following properties:

- `jwt.enabled`: Whether to enable JWT authentication. Default: `true`.
- `jwt.secret`: The secret key used to sign and verify JWT tokens. (Minimum 64 characters)
- `jwt.expiration-ms`: The expiration time of JWT tokens in milliseconds. Default: `86400000` (24 hours).
- `jwt.issuer`: The issuer of JWT tokens.
- `jwt.refresh-window-ms`: The refresh window time in milliseconds. Default: `300000` (5 mins).
- `jwt.blacklisted-cleanup-interval-ms`: The interval for cleaning up blacklisted tokens in milliseconds. Default: `600000` (10 mins).
- `jwt.excluded-paths`: The paths to exclude from JWT authentication. Default: `/api/auth/**`, `/swagger-ui/**`, `/v3/api-docs/**`.
- `jwt.token-prefix`: The prefix for JWT tokens. Default: `Bearer `.
- `jwt.token-header`: The header name for JWT tokens. Default: `Authorization`.

## Core Components

### JwtTokenService
The JwtTokenService provides methods for JWT token operations:

- `generateToken(String subject)` : Generate a token for a subject
- `generateToken(String subject, Map<String, Object> claims)` : Generate a token with custom claims
- `validateToken(String token)` : Validate a token and return its details
- `refreshToken(String token)` : Generate a new token while invalidating the old one
- `getSubjectFromToken(String token)` : Extract the subject from a token
- `isTokenExpired(String token)` : Check if a token is expired

### TokenBlacklistService

The TokenBlacklistService manages revoked tokens:

- `blacklistToken(String token, long expirationTime)` : Add a token to the blacklist
- `isBlacklisted(String token)` : Check if a token is blacklisted
By default, an in-memory implementation is provided, but you can create your own implementation by implementing the TokenBlacklistService interface.

## Spring Security Integration

The starter automatically configures Spring Security to use JWT authentication. To customize the security configuration, you can extend the provided classes or create your own configuration.

### Example Usage

Here's a simple example of how to use the JWT starter in your application:

```java
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JwtTokenService jwtTokenService;
    private final AuthenticationManager authenticationManager;

    public AuthController(JwtTokenService jwtTokenService, AuthenticationManager authenticationManager) {
        this.jwtTokenService = jwtTokenService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(),
                loginRequest.getPassword()
            )
        );
        
        SecurityContextHolder.getContext().setAuthentication(authentication);
        
        // Generate JWT token
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
            
        JwtToken token = jwtTokenService.generateToken(authentication.getName(), claims);
        
        return ResponseEntity.ok(new JwtResponse(token.getToken()));
    }
    
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody TokenRefreshRequest request) {
        JwtToken refreshedToken = jwtTokenService.refreshToken(request.getToken());
        return ResponseEntity.ok(new JwtResponse(refreshedToken.getToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody LogoutRequest request) {
        jwtTokenService.invalidateToken(request.getToken());
        return ResponseEntity.noContent().build();
    }
}
```

## Exception Handling

The starter provides custom exceptions for JWT-related errors:

- `JwtException` : Base exception for all JWT-related errors
- `TokenExpiredException` : Thrown when a token has expired
- `InvalidTokenException` : Thrown when a token is invalid

## Advanced Usage

### Custom JWT Token Service

You can provide your own implementation of `JwtTokenService` to customize token generation and validation:

```java
@Service
public class CustomJwtTokenService implements JwtTokenService {
    // Your custom implementation
}
```

### Custom Security Configuration

If you need more control over the security configuration, you can define your own `SecurityFilterChain` bean:

```java
@Configuration
public class SecurityConfig {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/public/**").permitAll()
                        .anyRequest().authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
```

### Custom Token Blacklist Implementation

By default, an in-memory implementation of `TokenBlacklistService` is provided. For production environments, you might want to implement a persistent solution:

```java
@Service
@Primary
public class JpaTokenBlacklistService implements TokenBlacklistService {
    
    private final BlacklistedTokenRepository tokenRepository;
    
    public JpaTokenBlacklistService(BlacklistedTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }
    
    @Override
    public void blacklistToken(String token, long expirationTime) {
        BlacklistedToken blacklistedToken = new BlacklistedToken();
        blacklistedToken.setToken(token);
        blacklistedToken.setExpirationTime(expirationTime);
        tokenRepository.save(blacklistedToken);
    }
    
    @Override
    public boolean isBlacklisted(String token) {
        return tokenRepository.existsByToken(token);
    }
    
    // Optional: Cleanup method to remove expired tokens
    @Scheduled(fixedRateString = "${jwt.blacklisted-cleanup-interval-ms:600000}")
    public void cleanupExpiredTokens() {
        tokenRepository.deleteByExpirationTimeLessThan(System.currentTimeMillis());
    }
}
```

### Custom Claims

You can add custom claims to your JWT tokens:

```java
Map<String, Object> claims = new HashMap<>();
claims.put("userId", user.getId());
claims.put("email", user.getEmail());
claims.put("roles", user.getRoles());

JwtToken token = jwtTokenService.generateToken(user.getUsername(), claims);
```

## Documentation
For detailed API documentation, please refer to the [Javadoc](https://javadoc.io/doc/io.github.seydoucisse/jwt-spring-boot-starter).

## License
This project is licensed under the MIT License - see the LICENSE file for details.