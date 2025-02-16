package com.ems.model;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Data
@Getter
@Setter
public class LoginUser {
    private String email;
    private String password;

    
}