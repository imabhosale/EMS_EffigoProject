package com.ems.service.serviceImpl;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import com.ems.model.Contact;
import com.ems.model.Entity.User;
import com.ems.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ems.model.Entity.Message;
import com.ems.repository.MessageDao;

import javax.swing.text.html.Option;

/**
 * This Service handles both the processing of messages and the contacts.
 */
@Service(value = "messageService")
public class MessageServiceImpl {
	@Autowired
	private MessageDao messageDao;

	@Autowired
	private UserService userService;

	public void addMessage(Message message) {
		messageDao.save(message);
	}
	
	public List<Message> getSenderMessages(Long senderId){
		return messageDao.findAll().stream()
				.filter(message -> message.getSenderId() == senderId)
				.collect(Collectors.toList());
	}
	
	public List<Message> getReceiverMessages(Long receiverId){
		return messageDao.findAll().stream()
				.filter(message -> message.getReceiverId() == receiverId)
				.collect(Collectors.toList());
	}
	
	public List<Message> getAllMessagesWithId(Long id1, Long id2){
		return messageDao.findAll().stream().
				filter(message -> (
						(Objects.equals(message.getReceiverId(), id1) && Objects.equals(message.getSenderId(), id2))||
						(Objects.equals(message.getSenderId(), id1) && Objects.equals(message.getReceiverId(), id2))
						)).
				collect(Collectors.toList());
	}
	
	public List<Message> getAllMessagesWithId(Long id){
		return messageDao.findAll().stream().
				filter(message -> (
						message.getReceiverId()==id || message.getSenderId()==id
				))
				.collect(Collectors.toList());
	}

	public List<Contact> getAllContacts(Long userId) {
		return getAllMessagesWithId(userId).stream()
				.map(message-> message.getSenderId()==userId ? message.getReceiverId() : message.getSenderId())
				.distinct()
				.map(uid -> userService.findByid(uid).get())
				.map(Contact::new)
				.collect(Collectors.toList());
	}

	public Optional<Contact> getContact(Long id){
		return userService.findByid(id)
				.map(Contact::new);
	}

	public List<Contact> searchContacts(String query){
		return userService.getAllUser().stream()
				.filter(user -> matchQuery(user, query))
				.map(Contact::new)
				.toList();
	}

	// Utility
	public Boolean matchQuery(User user, String query){
		return user.getEmail().startsWith(query) ||
			   user.getFirstName().startsWith(query) ||
			   user.getLastName().startsWith(query) ||
			   user.getMobile().startsWith(query);
	}
}