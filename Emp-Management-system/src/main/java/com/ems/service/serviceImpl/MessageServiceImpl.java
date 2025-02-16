package com.ems.service.serviceImpl;


import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ems.model.Message;
import com.ems.repository.MessageDao;

@Service(value = "messageService")
public class MessageServiceImpl {
	@Autowired
	private MessageDao messageDao;
	
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
						(message.getReceiverId()==id1 && message.getSenderId()==id2)||
						(message.getSenderId()==id1 && message.getReceiverId()==id2)
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
}