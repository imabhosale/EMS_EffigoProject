package com.ems.service;

import java.util.List;
import java.util.Optional;

import com.ems.util.Status;
import com.ems.util.StatusCounts;
import org.springframework.security.core.userdetails.UserDetails;

import com.ems.model.Entity.User;
import com.ems.model.dto.UserDto;

public interface UserService {

	User save(UserDto user);

	User createUser(UserDto user);

	User updateUser(Long userId, UserDto updatedUserDto);

	List<User> findAllAdmins();

	List<User> getAllUser();

	UserDetails loadUserByUsername(String email);

	Optional<User> findByEmail(String email);

	Optional<User> findByid(Long id);

	void makeUserAdmin(Long userId);

	StatusCounts getStatusCounts();

	UserDto registerUser(UserDto userDto);

	Optional<Long> getUserIdWithEmail(String email);

	Status getUserStatusByEmail(String email);
}