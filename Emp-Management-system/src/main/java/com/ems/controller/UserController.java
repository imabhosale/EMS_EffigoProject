package com.ems.controller;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import com.ems.model.Entity.File;
import com.ems.repository.FileDao;
import com.ems.service.FileService;
import com.ems.util.Status;
import com.ems.util.StatusCounts;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.ems.model.AuthToken;
import com.ems.model.LoginUser;
import com.ems.model.Entity.AccessHistory;
import com.ems.model.Entity.User;
import com.ems.model.dto.UserDto;
import com.ems.repository.UserDao;
import com.ems.service.FileUploaderService;
import com.ems.service.UserService;
import com.ems.service.serviceImpl.AccessHistoryServiceImpl;
import com.ems.service.serviceImpl.AuthenticationService;

import lombok.extern.slf4j.Slf4j;

/**
 * Rest Controller for Users end-point
 */
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/users")
@Slf4j
public class UserController {
	
	@Autowired
	AuthenticationService authenticationService;

	@Autowired
	private UserService userService;

	@Autowired
	private AccessHistoryServiceImpl accessHistoryService;

	@Autowired
	private FileUploaderService fileUploaderService;

	@Autowired
	private FileService fileService;

	// Authentication and Login/Registration

	@PostMapping("/authenticate")
	public ResponseEntity<?> authenticateUser(@RequestBody LoginUser loginUser) throws AuthenticationException {
		Optional<AuthToken> authToken = authenticationService.generateToken(loginUser);

		if (authToken.isPresent() && userService.getUserStatusByEmail(loginUser.getEmail())== Status.ACTIVE) {
			log.debug("Authentication Success for: {}", loginUser.getEmail());

			// Updating Access history
			userService.getUserIdWithEmail(loginUser.getEmail()).ifPresent(userId->
					accessHistoryService.loggedIn(userId,LocalDateTime.now()));

			return ResponseEntity.ok(authToken.get());
		}

		log.error("Authentication failed: Bad credentials for user {}", loginUser.getEmail());
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid email or password");
	}

	@PostMapping("/register")
	public UserDto registerUser(@RequestBody UserDto user) {
		return userService.registerUser(user);
	}

	// ADMIN ROLE

	@Secured("ADMIN")
	@PostMapping("/create")
	public User createUser(@RequestBody UserDto user) {
		return userService.createUser(user);
	}

	@Secured("ADMIN")
	@GetMapping("/find/all")
	public List<User> getAllUser() {
		return userService.getAllUser();
	}

	@Secured("ADMIN")
	@GetMapping("/accessHistory")
	public List<AccessHistory> getAccessHistory() {
		return accessHistoryService.getAllHistory();
	}

	// USER ROLE

	@Secured("USER")
	@GetMapping("/get/{id}")
	public ResponseEntity<User> getUserById(@PathVariable Long id) {
		Optional<User> updatedUser = userService.findByid(id);
		return updatedUser
				.map(ResponseEntity::ok)
				.orElse(ResponseEntity.notFound().build());
	}

	// NO ROLE Base AUTHORIZATION

	@GetMapping("/admins")
	public List<User> getAllAdmins() {
		return userService.findAllAdmins();
	}

	@PostMapping("/upload")
	public List<User> uploadAndCreateUsers(@RequestParam("file") MultipartFile file) {
		return fileUploaderService.uploadAndCreateUsers(file);
	}

	@PutMapping("/edit/{id}")
	public User updateUser(@PathVariable Long id, @RequestBody UserDto updatedUserDto) {
		return userService.updateUser(id, updatedUserDto);
	}

	@GetMapping("/find/{email}")
	public ResponseEntity<User> getUserByEmail(@PathVariable String email) {
		email = URLDecoder.decode(email, StandardCharsets.UTF_8);

		return userService.findByEmail(email)
				.map(ResponseEntity::ok)
				.orElseGet(() -> ResponseEntity.notFound().build());
	}

	@GetMapping("/stats")
	public StatusCounts getUserStatus() {
		return userService.getStatusCounts();
	}

	@GetMapping("/getId/{email}")
	public ResponseEntity<Long> getUserIdByMail(@PathVariable String email) {
		return userService.findByEmail(email)
				.map(user -> ResponseEntity.ok(user.getId()))
				.orElseGet(() -> ResponseEntity.notFound().build());
	}

	@PostMapping("/{userId}/make-admin")
	public String makeUserAdmin(@PathVariable Long userId) {
		userService.makeUserAdmin(userId);
		return "User with ID " + userId + " is now an Admin.";
	}

	@Transactional
	@PostMapping("/uploadFile/{userId}")
	public ResponseEntity<String> uploadFile(@PathVariable Long userId, @RequestParam("file") MultipartFile file) {
		try {
			String fileUrl = fileService.uploadAndSaveFileUrl(userId,file);
			return ResponseEntity.ok(fileUrl);
		} catch (Exception e) {
			throw new RuntimeException("File upload failed for user ID " + userId + ": " + e.getMessage());
		}
	}
}