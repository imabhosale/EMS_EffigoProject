package com.ems.config;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.ems.util.Role;

import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;

/**
 * Spring Security configuration to override default the Security Filter Chain. Disables the default
 * Security Configuration and enables method security with methods like @Secured, @PostAuthorize, etc,.
 */
@Configuration
@EnableWebSecurity 
@EnableMethodSecurity 
@Slf4j
public class WebSecurityConfiguration {

    @Resource(name = "userService")
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoderConfiguration passwordEncoder;

    @Autowired
    private CustomUnauthorizedEntryPoint unauthorizedEntryPoint;

    /**
     * Overrides The Default Security Filter Chain.
     * <ul>
     *		<li>Disables CORS and CSRF</li> 
     * 		<li>Setup authentication for URLs</li>
     * 		<li>Defines Response to Handle Exception</li>
     * 		<li>Disables Session</li>
     * 		<li>Add Custom JWT Filter</li>
     * </ul>
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    	
        http.cors().and().csrf().disable()
            .authorizeRequests()
            .requestMatchers("/users/authenticate", "/users/register").permitAll()
            .requestMatchers("/users/find/all").hasRole(Role.ADMIN.toString())
            .requestMatchers("/users/stats").hasRole(Role.ADMIN.toString())
            .anyRequest().authenticated()
            .and()
            .exceptionHandling().authenticationEntryPoint(unauthorizedEntryPoint).and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(jwtOncePerRequestAuthFilter(), UsernamePasswordAuthenticationFilter.class);

//        http
//		    .cors(cors -> cors.disable())
//		    .csrf(csrf -> csrf.disable())
//        	.authorizeHttpRequests(auth -> 
//	    		auth.requestMatchers("/users/authenticate", "/users/register").permitAll()
//	        		.requestMatchers("/users/find/all").hasRole(Role.ADMIN.toString())
//	                .requestMatchers("/users/stats").hasRole(Role.ADMIN.toString())
//	                .anyRequest().authenticated())
//	        .exceptionHandling(exp -> exp.authenticationEntryPoint(unauthorizedEntryPoint))
//	        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//        	.addFilterBefore(jwtOncePerRequestAuthFilter(), UsernamePasswordAuthenticationFilter.class);

    	log.info("Security Filter Chain Created");

        return http.build();
    }
    

    /**
     * Provides a <b>WebSecurityCustomizer</b> that disables security for the following URLs:
     * <ul>
     * 		<li>/users/authenticate</li>
     * 		<li>/users/register</li>
     * </ul>
     * They can be accessed without any authentication.
     */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().requestMatchers("/users/authenticate", "/users/register");
    }

    /**
     * Provides <b>JWTOncePerRequestAuthFilter</b> Filter.
     */
    @Bean
    public JwtOncePerRequestAuthFilter jwtOncePerRequestAuthFilter() throws Exception {
        return new JwtOncePerRequestAuthFilter();
    }

    /**
     * Overrides the Default authentication Manager. The Manager is configured to use the <b>BCryptPasswordEncoder</b> to encode passwords. 
     */
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        var authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        
        authenticationManagerBuilder
                   .userDetailsService(userDetailsService)
                   .passwordEncoder(passwordEncoder.encoder());
                   
        return authenticationManagerBuilder.build();
    }
}
