package com.ems.service.serviceImpl;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.ems.config.TokenUtil;
import com.ems.model.AuthToken;
import com.ems.model.LoginUser;

@Service
public class AuthenticationService {
	
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private TokenUtil jwtTokenUtil;
	
	public Optional<AuthToken> generateToken(LoginUser loginUser) throws AuthenticationException {
		try {
			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(loginUser.getEmail(), loginUser.getPassword()));
		
			String token = jwtTokenUtil.generateToken(authentication);
	
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			return Optional.of(new AuthToken(token));
		} catch (BadCredentialsException e) {
			
			return Optional.empty();
		
		}
	}

	public String getAuthenticatedUserMail(){
		return SecurityContextHolder.getContext().getAuthentication().getName();
	}
}
