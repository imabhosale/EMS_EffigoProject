package com.ems.service;

import com.ems.model.User;
import org.springframework.web.multipart.MultipartFile;
import java.util.List;

public interface FileUploaderService {
    List<User> uploadAndCreateUsers(MultipartFile file);
}
