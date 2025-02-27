package com.ems.model.dto;

import lombok.Data;

@Data
public class UserFileDTO {
	
	private int documentId;
    private String fileName;
    private String fileUrl;
    
}