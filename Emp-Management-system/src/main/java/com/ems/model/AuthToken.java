package com.ems.model;

import lombok.Data;

/**
 * Represents an authentication token.
 */
@Data
public class AuthToken {
    private String token;

    private long id;
    /**
     * Constructs a new AuthToken object.
     */
    public AuthToken() {
    }

    /**
     * Constructs a new AuthToken object with the specified token.
     * 
     * @param token the authentication token
     */
    public AuthToken(String token) {
        this.token = token;
    }

    /**
     * Returns the authentication token.
     * 
     * @return the authentication token
     */
    public String getToken() {
        return token;
    }

    /**
     * Sets the authentication token.
     * 
     * @param token the authentication token to be set
     */
    public void setToken(String token,long id) {
        this.token = token;
        this.id=id;
    }
}