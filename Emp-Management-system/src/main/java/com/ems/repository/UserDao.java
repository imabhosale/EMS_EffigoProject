package com.ems.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.ems.model.User;
import com.ems.model.UserStatus;

@Repository
public interface UserDao extends JpaRepository<User, Long> {
	//Optional<User> findByEmail(String email);

	 @Query("SELECT u FROM User u JOIN u.roles r WHERE r.name = 'ADMIN'")
	    List<User> findAllAdmins();
	 
	 
	 @Query("SELECT u FROM User u WHERE u.status = :status")
		List<User> findByStatus(@Param("status") UserStatus status);
	 
	 Optional<User> findByEmail(String email);
	 
	  int countByStatus(UserStatus status);
}