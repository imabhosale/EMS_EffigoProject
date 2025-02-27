package com.ems.config;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * A Utility Class to process JWT Tokens
 */
@Component
public class TokenUtil implements Serializable {

	private static final long serialVersionUID = 1L;

	// The below @Value fields are obtained from the application.properties
	
	@Value("${jwt.token.validity}")
	public long TOKEN_VALIDITY;

	@Value("${jwt.signing.key}")
	public String SIGNING_KEY;

	@Value("${jwt.authorities.key}")
	public String AUTHORITIES_KEY;

	/**
	 * Extract the username from the token, which is stored as subject in the claims.
	 */
	public String getUsernameFromToken(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}

	/**
	 * Extract the expiration date from the token.
	 */
	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

	/**
	 * Extracts the claims from the token, as specified by the claimsResolver.
	 */
	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	/**
	 * Returns the entire Claims from the token.
	 */
	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser()
				.setSigningKey(SIGNING_KEY)
				.parseClaimsJws(token)
				.getBody();
	}

	/**
	 * Check if the token is expired at the time of method call.
	 */
	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	/**
	 * Generate a new JWT token, with details from the authentication instance.
	 * 
	 * The Token Contains:
	 * <li><b>Subject</b>: set as the usermail.</li>
	 * <li><b>roles</b> : comma separated user roles, as additional claims.</li>
	 * <li><b>Issued time</b> : Time when the token was generated.</li>
	 * <li><b>Expiration time</b> : Validity period in milliseconds.</li>
	 * <li><b>Signing Algorithm</b> : Used to sign the token.</li>
	 */
	public String generateToken(Authentication authentication) {
		String authorities = authentication.getAuthorities().stream()
								.map(GrantedAuthority::getAuthority)
								.collect(Collectors.joining(","));

		return Jwts.builder()
				.setSubject(authentication.getName())
				.claim(AUTHORITIES_KEY, authorities) 
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + TOKEN_VALIDITY * 1000 * 60 * 30))
				.signWith(SignatureAlgorithm.HS256, SIGNING_KEY).compact();
	}

	/**
	 * Tests validity of the JWT token 
	 */
	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && 
				!isTokenExpired(token));
	}

	/**
	 * Generate the Authentication instance using the JWT token
	 */
	UsernamePasswordAuthenticationToken getAuthenticationToken(final String token, final Authentication existingAuth, final UserDetails userDetails) {

		final Claims claims = getAllClaimsFromToken(token);

		final var authorities = Arrays
				.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());

		return new UsernamePasswordAuthenticationToken(userDetails, "", authorities);
	}

}