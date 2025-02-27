package com.ems.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Represents an authentication token.
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthToken {
	
    private String token;
    private long id;
    
    public AuthToken(String token) {
    	this.token = token;
    }

}