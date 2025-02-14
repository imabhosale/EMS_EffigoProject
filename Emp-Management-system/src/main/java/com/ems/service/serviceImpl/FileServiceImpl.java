package com.ems.service.serviceImpl;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.PutObjectRequest;
import com.ems.service.IFileService;

@Service
public class FileServiceImpl implements IFileService {

    private static final Logger logger = LoggerFactory.getLogger(FileServiceImpl.class);

    private final AmazonS3 s3Client;
    private final String bucketName;

    public FileServiceImpl(
        @Value("${aws.accessKeyId}") String accessKey,
        @Value("${aws.secretAccessKey}") String secretKey,
        @Value("${aws.s3.region}") String region,
        @Value("${aws.s3.bucketName}") String bucketName
    ) {
        this.bucketName = bucketName;
        logger.info("Initializing S3 Client with bucket: {}", bucketName);
        
        BasicAWSCredentials credentials = new BasicAWSCredentials(accessKey, secretKey);
        this.s3Client = AmazonS3ClientBuilder.standard()
                .withRegion(Regions.fromName(region))
                .withCredentials(new AWSStaticCredentialsProvider(credentials))
                .build();

        if (!s3Client.doesBucketExistV2(bucketName)) {
            throw new IllegalArgumentException("S3 bucket does not exist: " + bucketName);
        }
    }

    @Override
    public String uploadFile(MultipartFile file, Long userId) {
        logger.info("Uploading file: {} for user ID: {}", file.getOriginalFilename(), userId);
        String fileName = "documents/" + userId + "/" + file.getOriginalFilename();
        File convertedFile = null;

        try {
            // Convert MultipartFile to File
            convertedFile = convertMultiPartToFile(file);
            convertedFile.deleteOnExit();  // Ensures cleanup on JVM exit

            // Upload file to S3
            s3Client.putObject(new PutObjectRequest(bucketName, fileName, convertedFile));
            String fileUrl = s3Client.getUrl(bucketName, fileName).toString();
            
            logger.info("File successfully uploaded to: {}", fileUrl);
            return fileUrl;
        } catch (Exception e) {
            logger.error("File upload failed", e);
            throw new RuntimeException("File upload failed: " + e.getMessage(), e);
        } finally {
            // Delete temporary file if it exists
            if (convertedFile != null && convertedFile.exists() && convertedFile.delete()) {
                logger.info("Temporary file deleted successfully");
            } else if (convertedFile != null && convertedFile.exists()) {
                logger.warn("Failed to delete temporary file: {}", convertedFile.getAbsolutePath());
            }
        }
    }

    private File convertMultiPartToFile(MultipartFile file) throws IOException {
        logger.info("Converting MultipartFile: {}", file.getOriginalFilename());
        Path tempFile = Files.createTempFile("upload_", file.getOriginalFilename());
        File convFile = tempFile.toFile();

        try (FileOutputStream fos = new FileOutputStream(convFile)) {
            fos.write(file.getBytes());
        }
        logger.info("File successfully converted: {}", convFile.getAbsolutePath());
        return convFile;
    }
}