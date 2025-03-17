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
package dev.scisse.jwt.exception;

/**
 * Exception thrown when a JWT token has expired.
 * <p>
 * This exception is thrown during token validation when the token's
 * expiration date has passed. It is a specific type of {@link JwtException}
 * that allows applications to handle expired tokens differently from
 * other JWT validation errors.
 * 
 * <p>
 * This exception is typically caught in authentication filters or token
 * validation services to provide appropriate responses for expired tokens,
 * such as prompting for re-authentication or attempting a token refresh.
 * 
 * @author Seydou CISSE
 * @since 0.1.0
 * @see dev.scisse.jwt.exception.JwtException
 * @see dev.scisse.jwt.service.JwtTokenService#validateToken(String)
 * @see dev.scisse.jwt.service.JwtTokenService#refreshToken(String)
 */
public class TokenExpiredException extends JwtException {
    
    /**
     * Constructs a new TokenExpiredException with the specified detail message.
     *
     * @param message the detail message (which is saved for later retrieval
     *                by the {@link #getMessage()} method)
     */
    public TokenExpiredException(String message) {
        super(message);
    }
    
    /**
     * Constructs a new TokenExpiredException with the specified detail message and cause.
     *
     * @param message the detail message (which is saved for later retrieval
     *                by the {@link #getMessage()} method)
     * @param cause   the cause (which is saved for later retrieval by the
     *                {@link #getCause()} method). A null value is permitted,
     *                and indicates that the cause is nonexistent or unknown.
     */
    public TokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}