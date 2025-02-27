package com.ems.config;

import java.io.IOException;
import java.io.Serializable;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * An <b>AuthenticationEntryPoint</b> instance.
 * Defines the response to send when an unauthenticated user tries to access a protected resource. 
 * <i>Response contains status code (401) and message as "Unauthenticated"</i>
 */
@Component
public class CustomUnauthorizedEntryPoint implements AuthenticationEntryPoint, Serializable {

	private static final long serialVersionUID = 1L;

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
		response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthenticated");
	}

}