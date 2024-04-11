package com.user.authenticationAndAuthorisation.user.Controllers;

import com.user.authenticationAndAuthorisation.user.UserModel;
import com.user.authenticationAndAuthorisation.user.UserRepository;
import com.user.authenticationAndAuthorisation.user.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("${api.users-url}")
@CrossOrigin("*")
public class Register {
    private static final Logger logger = LoggerFactory.getLogger(Register.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Value("${expirationValidAccount}")
    private int expirationValidAccount;


    /**
     * Registers a new user with the provided user information.
     *
     * @param userModel The user model containing user details.
     * @return ResponseEntity with a success message if registration is successful,
     *         or an error message if registration fails.
     */
    @PostMapping("/register")
    public ResponseEntity registerUser(@RequestBody UserModel userModel) {

        Map<String, Object> responseBody = new HashMap<>();

        try {
            String userName = userModel.getUserName();
            String email = userModel.getEmail();
            String password = userModel.getPassword();

            // Validate user name
            if (userName == null || userName.length() < 6) {
                responseBody.put("error", "User name must be at least 6 characters long.");
                return ResponseEntity.badRequest().body(responseBody);
            }

            // Check if the user name already exists
            if (userRepository.findByUserName(userName).isPresent()) {
                responseBody.put("error", "User name already exists.");
                return ResponseEntity.badRequest().body(responseBody);
            }

            // Validate email
            if (email == null || email.isEmpty()) {
                responseBody.put("error", "Email must not be empty.");
                return ResponseEntity.badRequest().body(responseBody);
            }

            // Check if the email already exists
            if (userRepository.findByEmail(email).isPresent()) {
                responseBody.put("error", "Email already exists.");
                return ResponseEntity.badRequest().body(responseBody);
            }

            // Validate password
            if (password == null || password.length() < 6) {
                responseBody.put("error", "Password must be at least 6 characters long.");
                return ResponseEntity.badRequest().body(responseBody);
            }

            // Register the user
            UserModel registeredUser = userService.registerUser(userName, email, password);

            if (registeredUser != null) {

                // Send the email
                String subject = "Verify Your Account";
                String text = "Hello " + userName + ",\n\n" +
                        "Thank you for registering with us. Please use the following verification code to activate your account:\n\n" +
                        registeredUser.getVerifyCode() + "\n\n" +
                        "This verification code is valid for " + (expirationValidAccount / 60) + " minute(s).\n\n" +
                        "If you did not create this account, please ignore this email.\n\n" +
                        "Best regards,\n\n" +
                        "The Team";

                userService.sendEmail(email, subject, text);

                responseBody.put("message", "User registered successfully.");
                return ResponseEntity.status(HttpStatus.CREATED).body(responseBody);
            }

            responseBody.put("error", "User registration failed.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseBody);

        } catch (Exception e) {
            e.printStackTrace();
            responseBody.put("error", "An error occurred during registration.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseBody);
        }

    }
}
