package com.ems.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ems.model.File;
import com.ems.model.User;

public interface FileDao extends JpaRepository<File, Long> {
	List<File> findByUser(User user);
}