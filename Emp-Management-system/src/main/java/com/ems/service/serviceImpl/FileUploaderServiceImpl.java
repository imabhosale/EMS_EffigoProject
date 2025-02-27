package com.ems.service.serviceImpl;

import java.io.BufferedReader;
import java.io.IOException; // Add this for IOException
import java.io.InputStream;
import java.io.InputStreamReader;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import com.ems.model.Entity.Role;
import com.ems.model.Entity.User;
import com.ems.model.dto.UserDto;
import com.ems.repository.UserDao;
import com.ems.service.FileUploaderService;
import com.ems.service.RoleService;
import com.ems.service.UserService;


@Service
public class FileUploaderServiceImpl implements FileUploaderService {

    @Autowired
    private UserDao userDao;

    @Autowired
    private RoleService roleService;

    @Autowired
    private UserService userService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private BCryptPasswordEncoder bcryptEncoder;

    @Override
    @Transactional
    public List<User> uploadAndCreateUsers(MultipartFile file) {
        List<User> createdUsers = new ArrayList<>();
        List<String> userFirstNames = new ArrayList<>(); // List to store first names of users created

        try (InputStream inputStream = file.getInputStream();
             BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
             CSVParser csvParser = new CSVParser(reader, CSVFormat.DEFAULT.withFirstRecordAsHeader())) {

            for (CSVRecord csvRecord : csvParser) {
                // Mapping CSV fields to UserDto
                UserDto userDto = new UserDto();
                userDto.setFirstName(csvRecord.get("firstName"));
                userDto.setLastName(csvRecord.get("lastName"));
                userDto.setEmail(csvRecord.get("email"));
                userDto.setMobile(csvRecord.get("mobile"));
                userDto.setPassword(csvRecord.get("password"));
                userDto.setStatus("PENDING");

                if (userDao.findByEmail(userDto.getEmail()).isPresent()) {
                    continue; // Skip if user already exists
                }

                // Convert UserDto to User entity
                User user = UserDto.convertToEntity(userDto);

                // Assign default role
                Set<Role> roles = new HashSet<>();
                roles.add(roleService.findByName("USER"));

                if (userDto.getEmail().endsWith("@mitaoe.ac.in")) {
                    roles.add(roleService.findByName("ADMIN"));
                }

                user.setRoles(roles);
                user.setRegisteredAt(Instant.now());
                user.setPassword(bcryptEncoder.encode(userDto.getPassword())); // Encoding password

                // Save user
                User savedUser = userDao.save(user);
                createdUsers.add(savedUser);
                userFirstNames.add(savedUser.getFirstName()); // Add user's first name to the list
            }

            if (!userFirstNames.isEmpty()) {
                // Get all admin emails
                List<User> adminEmailList = userService.findAllAdmins();
                List<String> emailList = adminEmailList.stream().map(us -> us.getEmail()).toList();

                // Create a common message listing the names of all new users
                String newUsersList = String.join(", ", userFirstNames);

                // Construct the email content
                String emailContent = "<html><body style='font-family: Arial, sans-serif; color: #333;'>"
                        + "<p>Dear Admin,</p>"
                        + "<p>We are pleased to inform you that the following users have successfully joined the platform BY CSV: </p>"
                        + "<p><strong>" + newUsersList + "</strong></p>"
                        + "<p>Kindly visit the Admin Panel to review and manage their accounts.</p>"
                        + "<p>If you have any questions or need assistance, feel free to reach out.</p>"
                        + "<p style='margin-top: 20px;'>Best regards,<br><strong>EMS (Effigo !!)</strong></p>"
                        + "</body></html>";

                // Send a single email to admins
                emailService.sendEmailToAdmins(emailList, emailContent);
            }

        } catch (IOException e) {
            throw new RuntimeException("Failed to process CSV file: " + e.getMessage(), e);
        }

        return createdUsers;
    }

}