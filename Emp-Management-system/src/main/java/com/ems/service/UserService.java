package com.ems.service;

import java.util.List;
import java.util.Optional;

import org.springframework.security.core.userdetails.UserDetails;

import com.ems.model.User;
import com.ems.model.UserDto;

public interface UserService {

	// Saves a user
	User save(UserDto user);

	// Retrieves all users
	List<User> findAll();

	// Retrieves a user by username
//    User findOne(String email);

	// public List<User> uploadAndCreateUsers(MultipartFile file);

	User getUserByEmail(String email);

	public User updateUser(Long userId, UserDto updatedUserDto);

	Optional<User> findByid(Long id);

	User createUser(UserDto user);

	// String sendHtmlEmail(String toEmail, String subject, String body);

	public UserDetails loadUserByUsername(String email);

	List<User> findAllAdmins();

	// public List<User> uploadAndCreateUsers(MultipartFile file);

	Optional<User> findByEmail(String email);

}