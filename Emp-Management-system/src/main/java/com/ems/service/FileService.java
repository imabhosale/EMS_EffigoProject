package com.ems.service;

import org.springframework.web.multipart.MultipartFile;

public interface FileService {

	String uploadFile(MultipartFile file, Long userId);

	String uploadAndSaveFileUrl(Long userId, MultipartFile file) throws Exception;
}