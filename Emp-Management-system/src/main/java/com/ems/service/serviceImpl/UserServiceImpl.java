package com.ems.service.serviceImpl;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.ems.model.Role;
import com.ems.model.User;
import com.ems.model.UserDto;
import com.ems.model.UserStatus;
import com.ems.repository.RoleDao;
import com.ems.repository.UserDao;
import com.ems.service.EmailService;
import com.ems.service.RoleService;
import com.ems.service.UserService;

@Service(value = "userService")
public class UserServiceImpl implements UserDetailsService, UserService {

	@Autowired
	private EmailService emailService;

	@Autowired
	private RoleService roleService;

	@Autowired
	private UserDao userDao;

	@Autowired
	private RoleDao roleDo;

	@Autowired
	private BCryptPasswordEncoder bcryptEncoder;

	@Autowired
	private ModelMapper modelMapper;

	@Override
	public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
		User user = userDao.findByEmail(email)
				.orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

		// ✅ Check if the user's status is ACTIVE (when using Enum)
		System.out.println(UserStatus.ACTIVE);
//		if (user.getStatus() != UserStatus.ACTIVE) { // Enum comparison
//			throw new DisabledException("User account is not active. Current status: " + user.getStatus());
//		}

		return org.springframework.security.core.userdetails.User.withUsername(user.getEmail())
				.password(user.getPassword()) // Ensure password is encoded
				.authorities(mapRolesToAuthorities(user.getRoles())) // ✅ Convert roles to GrantedAuthority
				.accountExpired(false).accountLocked(false).credentialsExpired(false).disabled(false).build();
	}

	private List<SimpleGrantedAuthority> mapRolesToAuthorities(Set<Role> roles) {
		return roles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName())) // Ensure ROLE_prefix
				.collect(Collectors.toList());
	}

	@Override
	public List<User> findAll() {
		return (List<User>) userDao.findAll();
	}

	@Override
	public List<User> findAllAdmins() {
		return userDao.findAllAdmins(); //
	}

	@Transactional
	@Override
	public User save(UserDto userDto) {
		User user = modelMapper.map(userDto, User.class);
		user.setPassword(bcryptEncoder.encode(userDto.getPassword()));

		Set<Role> roles = new HashSet<>();
		Role userRole = roleService.findByName("USER");
		roles.add(userRole);

		if (userDto.getEmail().endsWith("@mitaoe.ac.in")) {
			Role adminRole = roleService.findByName("ADMIN");
			roles.add(adminRole);
		}

//		List<String> adminList = new ArrayList<>();
//		adminList.add("abhishek.bhosale@mitaoe.ac.in");

		user.setRoles(roles);

		User user2 = userDao.save(user);
//		emailService.sendEmailToAdmins(adminList, user2.getFirstName());

		List<User> adminEmaiList = findAllAdmins();

		List<String> emaiList = adminEmaiList.stream().map(us -> us.getEmail()).toList();

		System.out.println(emaiList);

		emailService.sendEmailToAdmins(emaiList, user2.getFirstName());
		return user2;

	}

	@Transactional
	@Override
	public User createUser(UserDto userDto) {
		User user = modelMapper.map(userDto, User.class);
		user.setPassword(bcryptEncoder.encode(userDto.getPassword()));

		// Assign only the USER role
		Set<Role> roles = new HashSet<>();
		Role userRole = roleService.findByName("USER");
		roles.add(userRole);
		user.setRoles(roles);

		// Ensure registration time is set using Instant
		user.setRegisteredAt(Instant.now());

		User savedUser = userDao.save(user);

		List<User> adminEmaiList = findAllAdmins();

		List<String> emaiList = adminEmaiList.stream().map(us -> us.getEmail()).toList();

		System.out.println(emaiList);

		emailService.sendEmailToAdmins(emaiList, savedUser.getFirstName());
		return savedUser;
	}

	@Transactional
	@Override
	public User updateUser(Long userId, UserDto updatedUserDto) {
		User existingUser = userDao.findById(userId)
				.orElseThrow(() -> new RuntimeException("User not found with ID: " + userId));

		// Update allowed fields
		if (updatedUserDto.getFirstName() != null) {
			existingUser.setFirstName(updatedUserDto.getFirstName());
		}
		if (updatedUserDto.getLastName() != null) {
			existingUser.setLastName(updatedUserDto.getLastName());
		}
		if (updatedUserDto.getMobile() != null) {
			existingUser.setMobile(updatedUserDto.getMobile());
		}
		if (updatedUserDto.getStatus() != null) {
			try {
				UserStatus newStatus = UserStatus.valueOf(updatedUserDto.getStatus().toUpperCase()); // Convert String
																										// to Enum
				existingUser.setStatus(newStatus);

				// If the status is ACTIVE, send an email to the user
				if (newStatus == UserStatus.ACTIVE) {
					emailService.sendAccountActivationEmail(existingUser.getEmail(), existingUser.getFirstName());
				}
			} catch (IllegalArgumentException e) {
				throw new RuntimeException("Invalid user status: " + updatedUserDto.getStatus());
			}
		}

		return userDao.save(existingUser);
	}

	@Override
	public Optional<User> findByid(Long id) {
		Optional<User> user = userDao.findById(id);
		return user;
	}

	@Override
	public Optional<User> findByEmail(String email) {
		return userDao.findByEmail(email);
	}

	@Transactional
	public void makeUserAdmin(Long userId) {
		if (!userDao.existsById(userId)) {
			throw new RuntimeException("User with ID " + userId + " not found.");
		}
		roleDo.makeUserAdmin(userId);
	}

}