package com.ems.model;

import lombok.Data;

@Data
public class UserFileDTO {
	private int documentId;
    private String fileName;
    private String fileUrl;
}