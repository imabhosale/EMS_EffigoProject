package com.ems.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ems.model.Entity.File;

public interface FileDao extends JpaRepository<File, Long> {
	
}