package com.ems.model;

import java.time.LocalDateTime;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class Message {
	@Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE)
	Long id;
	
	Long senderId;
	Long receiverId;
	String Message;
	LocalDateTime time;
	
	
	public Message() {
		super();
	}


	public Message(Long id, Long senderId, Long receiverId, String message, LocalDateTime time) {
		super();
		this.id = id;
		this.senderId = senderId;
		this.receiverId = receiverId;
		Message = message;
		this.time = time;
	}


	public Message(Long senderId, Long receiverId, String message, LocalDateTime time) {
		super();
		this.senderId = senderId;
		this.receiverId = receiverId;
		Message = message;
		this.time = time;
	}

	
	
	
	public Long getId() {
		return id;
	}


	public void setId(Long id) {
		this.id = id;
	}


	public Long getSenderId() {
		return senderId;
	}


	public void setSenderId(Long senderId) {
		this.senderId = senderId;
	}


	public Long getReceiverId() {
		return receiverId;
	}


	public void setReceiverId(Long receiverId) {
		this.receiverId = receiverId;
	}


	public String getMessage() {
		return Message;
	}


	public void setMessage(String message) {
		Message = message;
	}


	public LocalDateTime getTime() {
		return time;
	}


	public void setTime(LocalDateTime time) {
		this.time = time;
	}


	public String toString() {
		return "Message [id=" + id + ", senderId=" + senderId + ", receiverId=" + receiverId + ", Message=" + Message
				+ ", time=" + time + "]";
	}
}
