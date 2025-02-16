package com.ems.model;

import java.util.List;

import org.modelmapper.ModelMapper;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {

    private String firstName;
    private String lastName;
    private String email;
    private String mobile;
    private String password;
    private String status; // String type for easier API handling
    private List<UserFileDTO> files;

    public static User convertToEntity(UserDto userDto) {
        ModelMapper modelMapper = new ModelMapper();
        User user = modelMapper.map(userDto, User.class);
        
        
        // Convert String status to Enum
        try {
            user.setStatus(UserStatus.valueOf(userDto.getStatus().toUpperCase())); // Ensures proper case conversion
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("Invalid user status: " + userDto.getStatus());
        }

        return user;
    }
}
