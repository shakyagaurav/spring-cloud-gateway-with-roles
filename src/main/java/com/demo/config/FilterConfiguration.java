package com.demo.config;

import com.demo.security.AuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfiguration {

    @Bean
    AuthenticationFilter getFilter(){
        return new AuthenticationFilter();
    }
}
