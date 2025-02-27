package com.ems.controller;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import com.ems.service.serviceImpl.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ems.model.Contact;
import com.ems.model.Entity.Message;
import com.ems.service.UserService;
import com.ems.service.serviceImpl.MessageServiceImpl;

/**
 * Rest Controller for managing <b>Messages</b> and <b>Contacts</b> (For purpose of messaging feature).
 */
@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/message")
public class MessageController {
	
	@Autowired
	private MessageServiceImpl messageService;
	
	@Autowired 
	private UserService userService;

	@Autowired
	AuthenticationService authenticationService;

	@PostMapping("/add")
	String addMessage(@RequestBody Message message) {
		message.setTime(LocalDateTime.now());
		messageService.addMessage(message);
		return "Added Message";
	}
	
	@GetMapping("/getAll/{oppositionId}")
	List<Message> getMessages(@PathVariable Long oppositionId){
		String userMail = authenticationService.getAuthenticatedUserMail();

		return userService.getUserIdWithEmail(userMail)
				.map(userId -> messageService.getAllMessagesWithId(userId, oppositionId))
				.orElse(Collections.emptyList());
	}
	
	@GetMapping("/getAllContacts")
	List<Contact> getAllContacts(){
		String userMail = authenticationService.getAuthenticatedUserMail();

		Long userId = userService.getUserIdWithEmail(userMail).orElse(0L);
		
		return messageService.getAllContacts(userId);
	}
		
	@GetMapping("/getContact/{id}")
	ResponseEntity<Contact> getContact(@PathVariable Long id) {
		return messageService.getContact(id)
				.map(ResponseEntity::ok)
				.orElseGet(() -> ResponseEntity.notFound().build());
	}
	
	@GetMapping("/searchContact/{query}")
	List<Contact> searchContactByQuery(@PathVariable String query){
		return messageService.searchContacts(query);
	}
}