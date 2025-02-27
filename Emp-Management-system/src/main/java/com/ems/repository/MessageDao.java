package com.ems.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ems.model.Entity.Message;

public interface MessageDao extends JpaRepository<Message, Long> {
    
}
