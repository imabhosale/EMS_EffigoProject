package com.ems.model;

import java.util.Collections;
import java.util.List;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class Contact {
    private long id;
    private String firstName;
    private String lastName;
    private String email;
    private String mobile;
    private List<String> role;
    
    public Contact(User user) {
    	this.id = user.getId();
    	this.firstName = user.getFirstName();
    	this.lastName = user.getLastName();
    	this.email = user.getEmail();
    	this.mobile = user.getMobile();
    	this.role = user.getRoles().stream().map(role -> role.getName()).toList();
    }
}
