package com.ems.service;

import org.springframework.web.multipart.MultipartFile;

public interface IFileService {

	String uploadFile(MultipartFile file, Long userId);
}