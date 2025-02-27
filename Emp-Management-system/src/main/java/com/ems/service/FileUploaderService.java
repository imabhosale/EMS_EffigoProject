package com.ems.service;

import java.util.List;

import org.springframework.web.multipart.MultipartFile;

import com.ems.model.Entity.User;

public interface FileUploaderService {

	List<User> uploadAndCreateUsers(MultipartFile file);

}
