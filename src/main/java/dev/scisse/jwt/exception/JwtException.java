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
 * Base exception for all JWT-related errors.
 * <p>
 * This exception is thrown when there are issues with JWT token generation,
 * validation, or processing. It serves as the parent class for more specific
 * JWT exceptions like {@link TokenExpiredException}.
 * </p>
 * <p>
 * Common scenarios where this exception might be thrown include:
 * <ul>
 *   <li>Invalid token format or signature</li>
 *   <li>Missing required claims</li>
 *   <li>Token tampering detection</li>
 *   <li>Token blacklisting</li>
 *   <li>Other JWT processing errors</li>
 * </ul>
 * </p>
 * <p>
 * This exception extends {@link RuntimeException}, making it an unchecked
 * exception that doesn't require explicit handling in method signatures.
 * </p>
 * 
 * @author Seydou CISSE
 * @since 0.1.0
 * @see dev.scisse.jwt.exception.TokenExpiredException
 * @see dev.scisse.jwt.service.JwtTokenService
 */
public class JwtException extends RuntimeException {
    
    /**
     * Constructs a new JwtException with the specified detail message.
     *
     * @param message the detail message (which is saved for later retrieval
     *                by the {@link #getMessage()} method)
     */
    public JwtException(String message) {
        super(message);
    }
    
    /**
     * Constructs a new JwtException with the specified detail message and cause.
     *
     * @param message the detail message (which is saved for later retrieval
     *                by the {@link #getMessage()} method)
     * @param cause   the cause (which is saved for later retrieval by the
     *                {@link #getCause()} method). A null value is permitted,
     *                and indicates that the cause is nonexistent or unknown.
     */
    public JwtException(String message, Throwable cause) {
        super(message, cause);
    }
}