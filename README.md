# JWT Spring Boot Starter

[![Maven Central](https://img.shields.io/maven-central/v/io.github.seydoucisse/jwt-spring-boot-starter)](https://maven-badges.herokuapp.com/maven-central/io.github.seydoucisse/jwt-spring-boot-starter) [![Javadoc](https://javadoc.io/badge2/io.github.seydoucisse/jwt-spring-boot-starter/javadoc.svg)](https://javadoc.io/doc/io.github.seydoucisse/jwt-spring-boot-starter) [![Build Status](https://img.shields.io/github/actions/workflow/status/seydoucisse/jwt-spring-boot-starter/build.yml?branch=main)](https://github.com/seydoucisse/jwt-spring-boot-starter/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A flexible Spring Boot starter for JWT (JSON Web Token) authentication that automatically configures JWT functionality in Spring Boot applications.

## Features

- Automatic JWT configuration with sensible defaults
- Customizable JWT properties
- Token generation and validation
- Spring Security integration
- Support for custom claims and roles
- Token blacklisting for invalidation
- Token refresh capabilities

## Getting Started

### Prerequisites

- Java 17+
- Spring Boot 3.3.x or higher

### Installation

Add the dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>dev.scisse</groupId>
    <artifactId>jwt-spring-boot-starter</artifactId>
    <version>0.1</version>
</dependency>
```

## Configuration

1. Add required properties in `application.properties` or `application.yml`:
   - `jwt.secret`: Your JWT signing key
   - `jwt.issuer`: Your application name

2. Implement `UserDetailsService`:
   - Create a service class that implements `UserDetailsService`
   - Override `loadUserByUsername()` method
   - Connect to your user data source

3. Optional: Customize the configuration
   - Override default JWT properties
   - Implement custom security configuration
   - Add custom token blacklist service

For detailed configuration options, see the [Configuration Properties](#configuration-properties) section below. For customization options, see the [Customization](#customization) section.


### Configuration Properties

The starter requires minimal configuration. You must set the following required properties in your `application.properties` or `application.yml` file:

```properties
# Required JWT Configuration
jwt.secret=yourSecretKey     # REQUIRED: Secret key used for signing JWT tokens
jwt.issuer=your-app          # REQUIRED: Issuer of the JWT tokens

# Optional JWT Configuration
jwt.expiration-ms=86400000   # Optional: Token expiration time in milliseconds (default: 24 hours)
jwt.blacklisted-cleanup-interval-ms=600000  # Optional: Interval for cleaning up blacklisted tokens in milliseconds (default: 10 minutes)
jwt.excluded-paths=/api/public/**,/swagger-ui/**  # Optional: Paths to exclude from JWT authentication
jwt.enabled=true             # Optional: Whether to enable JWT authentication
jwt.header-name=Authorization # Optional: Header name for the JWT token
jwt.token-prefix=Bearer      # Optional: Token prefix in the Authorization header
```

### UserDetailsService Implementation
This starter requires a UserDetailsService implementation in your application. For example:

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

The JWT authentication filter will use this service to load user details when validating tokens.

## Usage

### Generating JWT Tokens

```java
private final JwtTokenService jwtTokenService;

// ...

public String createToken(String username) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("roles", List.of("ROLE_USER"));
    
    JwtToken jwtToken = jwtTokenService.generateToken(username, claims);
    return jwtToken.getToken();
}
```

### Validating JWT Tokens

```java
private final JwtTokenService jwtTokenService;

// ...

public boolean validateToken(String token) {
    try {
        JwtToken jwtToken = jwtTokenService.validateToken(token);
        return true;
    } catch (Exception e) {
        return false;
    }
}
```

### Refreshing tokens

```java
private final JwtTokenService jwtTokenService;

// ...

public String refreshToken(String oldToken) {
    try {
        JwtToken refreshedToken = jwtTokenService.refreshToken(oldToken);
        return refreshedToken.getToken();
    } catch (JwtException e) {
        // Handle token refresh failure
        return null;
    }
}
```

## Customization

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
public class RedisTokenBlacklistService implements TokenBlacklistService {
    // Redis-based implementation for token blacklisting
}
```

## Examples

### Authentication Controller Example

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
            new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );
        
        SecurityContextHolder.getContext().setAuthentication(authentication);
        JwtToken jwtToken = jwtTokenService.generateToken(authentication.getName());
        
        return ResponseEntity.ok(new JwtResponse(jwtToken.getToken()));
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


## Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## Documentation
For detailed API documentation, please refer to the [Javadoc](https://javadoc.io/doc/io.github.seydoucisse/jwt-spring-boot-starter).

## License

MIT
