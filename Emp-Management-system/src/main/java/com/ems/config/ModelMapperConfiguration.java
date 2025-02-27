package com.ems.config;

import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * A Configuration class to provide <b>ModelMapper</b> Instance.
 * 
 * The instance will be used to map objects between Entity and DTO.
 */
@Configuration
public class ModelMapperConfiguration {

    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }
    
}
