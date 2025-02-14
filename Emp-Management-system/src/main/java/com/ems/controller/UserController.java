package com.ems.controller;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.ems.config.TokenProvider;
import com.ems.model.AuthToken;
import com.ems.model.LoginUser;
import com.ems.model.User;
import com.ems.model.UserDto;
import com.ems.service.FileUploaderService;
import com.ems.service.UserService;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/users")
public class UserController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private TokenProvider jwtTokenUtil;

	@Autowired
	private UserService userService;

	@RequestMapping(value = "/authenticate", method = RequestMethod.POST)
	public ResponseEntity<?> generateToken(@RequestBody LoginUser loginUser) throws AuthenticationException {
		System.out.println("Attempting authentication for: " + loginUser.getEmail());

		try {
			Authentication authentication = authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(loginUser.getEmail(), loginUser.getPassword()));


			SecurityContextHolder.getContext().setAuthentication(authentication);
			String token = jwtTokenUtil.generateToken(authentication);
			return ResponseEntity.ok(new AuthToken(token));

		} catch (BadCredentialsException e) {
			System.out.println("Authentication failed: Bad credentials for user " + loginUser.getEmail());
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
		}
	}

	/**
	 * Saves a new user.
	 *
	 * @param user The user to be saved.
	 * @return The saved user.
	 */
	@RequestMapping(value = "/register", method = RequestMethod.POST)
	public User saveUser(@RequestBody UserDto user) {
		return userService.save(user);
	}

	@PreAuthorize("hasRole('ADMIN')")
	@RequestMapping(value = "/adminping", method = RequestMethod.GET)
	public String adminPing() {
		return "Only Admins Can Read This";
	}

	/**
	 * Returns a message that can be accessed by any user.
	 *
	 * @return A message that can be accessed by any user.
	 */
	@PreAuthorize("hasRole('USER')")
	@RequestMapping(value = "/userping", method = RequestMethod.GET)
	public String userPing() {
		return "Any User Can Read This";
	}

	@PreAuthorize("hasRole('ADMIN')")
	@RequestMapping(value = "/create", method = RequestMethod.POST)
	public User createEmployee(@RequestBody UserDto user) {
		return userService.createUser(user);
	}

	@PreAuthorize("hasRole('ADMIN')")
	@RequestMapping(value = "/find/all", method = RequestMethod.GET)
	public List<User> getAllList() {
		return userService.findAll();
	}

	@GetMapping("/admins")
	public List<User> getAllAdmins() {
		return userService.findAllAdmins(); // ✅ Returns list of admin users
	}

	@Autowired
	private FileUploaderService fileUploaderService;

	@PostMapping("/upload")
	public List<User> uploadUsers(@RequestParam("file") MultipartFile file) {
		return fileUploaderService.uploadAndCreateUsers(file);
	}

	@PutMapping("/edit/{id}")
	public ResponseEntity<User> updateUser(@PathVariable Long id, @RequestBody UserDto updatedUserDto) {
		System.out.println("abhiii  user edit");
		User updatedUser = userService.updateUser(id, updatedUserDto);
		return ResponseEntity.ok(updatedUser);
	}

	@PreAuthorize("hasRole('USER')")
	@GetMapping("/get/{id}")
	public ResponseEntity<Optional<User>> GetUserByUserID(@PathVariable Long id) {
		System.out.println("abhiii " + id);
		Optional<User> updatedUser = userService.findByid(id);
		return ResponseEntity.ok(updatedUser);
	}


	@GetMapping("/find/{email}")
	public ResponseEntity<User> getUserByEmail(@PathVariable String email) {
		// ✅ Decode email properly
		String decodedEmail = URLDecoder.decode(email, StandardCharsets.UTF_8);
		System.out.println("Decoded Email: " + decodedEmail); // Debugging

		Optional<User> user = userService.findByEmail(decodedEmail);
		return user.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
	}
	
	@GetMapping("/{userId}/files")
	public ResponseEntity<List<Map<String, String>>> getUserFiles(@PathVariable Long userId) {
	    Optional<User> userOptional = userService.findByid(userId);
	    User user = userOptional.get();
	    
	    // Create a list of maps containing both filename and file URL
	    List<Map<String, String>> fileDetails = user.getFiles().stream()
	            .map(file -> {
	                Map<String, String> fileMap = new HashMap<>();
	                fileMap.put("name", file.getName());  // Assuming 'getName()' returns the file name
	                fileMap.put("fileUrl", file.getFileUrl());  // Assuming 'getFileUrl()' returns the URL
	                return fileMap;
	            })
	            .collect(Collectors.toList());

	    return ResponseEntity.ok(fileDetails);
	}

	


}
