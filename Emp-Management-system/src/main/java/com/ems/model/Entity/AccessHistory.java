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
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AccessHistory {

	@Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE)
	Long id;

	Long userId;
	LocalDateTime time;
	Boolean Status;

	public AccessHistory(Long userId, LocalDateTime time, Boolean status) {
		super();
		this.userId = userId;
		this.time = time;
		this.Status = status;
	}

}
