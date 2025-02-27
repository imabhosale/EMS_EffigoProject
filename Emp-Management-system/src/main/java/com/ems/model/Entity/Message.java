package com.ems.model.Entity;

import java.time.LocalDateTime;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Data
public class Message {
	
	@Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE)
	Long id;
	
	Long senderId;
	Long receiverId;
	String Message;
	LocalDateTime time;

	public Message(Long senderId, Long receiverId, String message, LocalDateTime time) {
		super();
		this.senderId = senderId;
		this.receiverId = receiverId;
		Message = message;
		this.time = time;
	}

}
