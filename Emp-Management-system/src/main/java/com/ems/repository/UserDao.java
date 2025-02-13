package com.ems.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import com.ems.model.User;

@Repository
public interface UserDao extends CrudRepository<User, Long> {
	//Optional<User> findByEmail(String email);

	 @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = 'ADMIN'")
	    List<User> findAllAdmins();
	 
	 Optional<User> findByEmail(String email);
}