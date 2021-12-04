package com.user;

import java.util.ArrayList;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.user.domain.Role;
import com.user.domain.User;
import com.user.service.UserService;

@SpringBootApplication
public class UserServiceJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(UserServiceJwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	CommandLineRunner runner(UserService userService) {
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
			
			userService.saveUser(new User(null, "jose Alvino", "jose", "12345", new ArrayList<>() ));
			userService.saveUser(new User(null, "john Travolta", "jhon", "12345", new ArrayList<>() ));
			userService.saveUser(new User(null, "Will Smith", "will", "12345", new ArrayList<>() ));
			userService.saveUser(new User(null, "Jim Carry", "jim", "12345", new ArrayList<>() ));
		
			userService.addRoleToUser("jose", "ROLE_USER");
			userService.addRoleToUser("jose", "ROLE_MANAGER");
			userService.addRoleToUser("will", "ROLE_MANAGER");
			userService.addRoleToUser("jim", "ROLE_ADMIN");
			userService.addRoleToUser("jhon", "ROLE_USER");
			userService.addRoleToUser("jhon", "ROLE_MANAGER");
			userService.addRoleToUser("jhon", "ROLE_ADMIN");
			userService.addRoleToUser("jhon", "ROLE_SUPER_ADMIN");
		};
	}
}
