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

import com.ems.model.Role;
import com.ems.model.User;
import com.ems.model.UserDto;
import com.ems.repository.UserDao;
import com.ems.service.EmailService;
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
                List<User> adminEmaiList = userService.findAllAdmins();

                List<String> emaiList = adminEmaiList.stream().map(us -> us.getEmail()).toList();

                System.out.println(emaiList);

                emailService.sendEmailToAdmins(emaiList, savedUser.getFirstName());
            }

        } catch (IOException e) {
            throw new RuntimeException("Failed to process CSV file: " + e.getMessage(), e);
        }

        return createdUsers;
    }
}