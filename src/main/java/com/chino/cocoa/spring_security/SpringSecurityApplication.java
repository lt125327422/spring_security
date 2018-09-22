package com.chino.cocoa.spring_security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
//@Configuration
//@EnableAutoConfiguration
//@ComponentScan

@RestController
@Controller
//@RestController

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SpringSecurityApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }

    @RequestMapping("/")
    public String home() {
        return "this is spring boot home index ";
    }

    //11d9db2a-5b74-4b9a-9ffd-5dc4b25e2dfd
    @RequestMapping("/chino")
    public String goToChinoHome() {
        return "this is spring boot home that chino home ";
    }

    /**
     * 前面必须加上ROLE_
     * <p>
     * note 只有role为admin才能登陆
     *
     * @return
     */
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @RequestMapping("/cocoa")
    public String goUser() {
        return "this is spring boot home that user home ";
    }

}
