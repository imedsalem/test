package com.user.authenticationAndAuthorisation;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

//@SpringBootApplication
@SpringBootApplication(exclude = { SecurityAutoConfiguration.class })
public class AuthenticationAndAuthorisationApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthenticationAndAuthorisationApplication.class, args);
	}

}
