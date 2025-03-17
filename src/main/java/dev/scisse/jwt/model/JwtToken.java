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
package dev.scisse.jwt.model;

import java.util.Date;
import java.util.Map;

/**
 * Represents a JWT token with its claims and metadata.
 * <p>
 * This class encapsulates all the information related to a JWT token, including
 * the token string itself, the subject (typically a username or user ID),
 * issuance and expiration dates, and any additional claims.
 * </p>
 * 
 * @author Seydou CISSE
 * @since 0.1.0
 */
public class JwtToken {
    private String token;
    private String subject;
    private Date issuedAt;
    private Date expiration;
    private Map<String, Object> claims;

    /**
     * Default constructor for JwtToken.
     */
    public JwtToken() {
    }

    /**
     * Constructs a JwtToken with all properties.
     *
     * @param token      The JWT token string
     * @param subject    The subject of the token (typically a username or user ID)
     * @param issuedAt   The date when the token was issued
     * @param expiration The date when the token will expire
     * @param claims     A map of additional claims included in the token
     */
    public JwtToken(String token, String subject, Date issuedAt, Date expiration, Map<String, Object> claims) {
        this.token = token;
        this.subject = subject;
        this.issuedAt = issuedAt;
        this.expiration = expiration;
        this.claims = claims;
    }

    /**
     * Gets the JWT token string.
     *
     * @return The JWT token string
     */
    public String getToken() {
        return token;
    }

    /**
     * Sets the JWT token string.
     *
     * @param token The JWT token string to set
     */
    public void setToken(String token) {
        this.token = token;
    }

    /**
     * Gets the subject of the token.
     *
     * @return The subject (typically a username or user ID)
     */
    public String getSubject() {
        return subject;
    }

    /**
     * Sets the subject of the token.
     *
     * @param subject The subject to set
     */
    public void setSubject(String subject) {
        this.subject = subject;
    }

    /**
     * Gets the issuance date of the token.
     *
     * @return The date when the token was issued
     */
    public Date getIssuedAt() {
        return issuedAt;
    }

    /**
     * Sets the issuance date of the token.
     *
     * @param issuedAt The issuance date to set
     */
    public void setIssuedAt(Date issuedAt) {
        this.issuedAt = issuedAt;
    }

    /**
     * Gets the expiration date of the token.
     *
     * @return The date when the token will expire
     */
    public Date getExpiration() {
        return expiration;
    }

    /**
     * Sets the expiration date of the token.
     *
     * @param expiration The expiration date to set
     */
    public void setExpiration(Date expiration) {
        this.expiration = expiration;
    }

    /**
     * Gets the additional claims included in the token.
     *
     * @return A map of additional claims
     */
    public Map<String, Object> getClaims() {
        return claims;
    }

    /**
     * Sets the additional claims for the token.
     *
     * @param claims A map of additional claims to set
     */
    public void setClaims(Map<String, Object> claims) {
        this.claims = claims;
    }
}