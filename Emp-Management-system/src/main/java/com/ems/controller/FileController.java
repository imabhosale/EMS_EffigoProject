package com.ems.controller;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.ems.model.File;
import com.ems.model.User;
import com.ems.repository.FileDao;
import com.ems.repository.UserDao;
import com.ems.service.IFileService;
import com.ems.service.UserService;

import jakarta.transaction.Transactional;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
//@RequestMapping("/users/file")
public class FileController {
	
	@Autowired
	private UserDao userRepository;

    @Autowired
    private IFileService fileService;
    
    @Autowired
    private FileDao fileDao;

    @PostMapping("/users/uploadFile/{userId}")
    @Transactional
    public ResponseEntity<String> uploadFile(
        @PathVariable Long userId,
        @RequestParam("file") MultipartFile file) {

    	
    	
    	
    	User existingUser = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User with ID " + userId + " not found"));

        try {
        	//int ud=(int) userId
            String fileUrl = fileService.uploadFile(file, userId);
            
            // Save file details to user_files table
            File userFile = new File(existingUser, file.getOriginalFilename(), fileUrl);
            fileDao.save(userFile);

            return ResponseEntity.ok().body(fileUrl);
        } catch (Exception e) {
            throw new RuntimeException("File upload failed for user ID " + userId + ": " + e.getMessage());
        }
    }
}