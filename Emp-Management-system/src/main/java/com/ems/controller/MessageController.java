package com.ems.controller;


import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ems.model.Message;
import com.ems.service.UserService;
import com.ems.service.serviceImpl.MessageServiceImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/message")
public class MessageController {
	
	@Autowired
	private MessageServiceImpl messageService;
	
	@Autowired 
	private UserService userService;
	
	
	@PostMapping("/add")
	String addMessage(@RequestBody Message message) {
		message.setTime(LocalDateTime.now());
		messageService.addMessage(message);
		return "Added Message";
	}
	
	@GetMapping("/getAll/{oppositionId}")
	List<Message> getMessages(@PathVariable Long oppositionId){
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String userMail = authentication.getName();

		
		System.out.println(">>>>"  + userMail);
		
		Long userId = userService.findAll().stream()
				.filter(user_ -> userMail.equals(user_.getEmail()))
				.findFirst().get().getId();	
		
		
		System.out.println("UID" + userId);
		return messageService.getAllMessagesWithId(userId, oppositionId);
	}
	
	@GetMapping("/getAllContacts")
	List<Long> getAllContacts(){
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String userMail = authentication.getName();

		System.out.println(">>>>"  + userMail);
		
		Long userId = userService.findAll().stream()
				.filter(user_ -> userMail.equals(user_.getEmail()))
				.findFirst().get().getId();	
		
		return messageService.getAllMessagesWithId(userId).stream()
				.map(message-> message.getSenderId()==userId ? message.getReceiverId() : message.getSenderId())
				.distinct()
				.collect(Collectors.toList());
	}
}