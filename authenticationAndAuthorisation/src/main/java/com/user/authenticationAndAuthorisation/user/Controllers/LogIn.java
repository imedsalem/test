package com.user.authenticationAndAuthorisation.user.Controllers;

import com.user.authenticationAndAuthorisation.user.JwtUtil;
import com.user.authenticationAndAuthorisation.user.UserModel;
import com.user.authenticationAndAuthorisation.user.UserRepository;
import com.user.authenticationAndAuthorisation.user.UserService;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("${api.users-url}")
@CrossOrigin("*")
public class LogIn {

    private static final Logger logger = LoggerFactory.getLogger(Register.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${expirationAccessToken}")
    private int expirationAccessToken;

    @Value("${expirationRefreshToken}")
    private int expirationRefreshToken;

    @Value("${nameAccessToken}")
    private String nameAccessToken;

    /**
     * Handles user login by verifying the provided credentials and generating access and refresh tokens.
     *
     * @param userModel The user model containing user email and password.
     * @param response The HTTP response object.
     * @return ResponseEntity with a success message if login is successful,
     *         or an error message if login fails.
     */
    @PostMapping("/logIn")
    public ResponseEntity logIn(@RequestBody UserModel userModel, HttpServletResponse response) {
        Map<String, Object> responseBody = new HashMap<>();

        try {
            String email = userModel.getEmail();
            String password = userModel.getPassword();

            // Check if the email exists
            Optional<UserModel> existingUser = userRepository.findByEmail(email);
            if (!existingUser.isPresent()) {
                responseBody.put("error", "Incorrect Email or password.");
                return ResponseEntity.badRequest().body(responseBody);
            }

            UserModel user = existingUser.get();

            // Compare the provided password with the stored hashed password
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            if (!passwordEncoder.matches(password, user.getPassword())) {
                responseBody.put("error", "Incorrect Email or password.");
                return ResponseEntity.badRequest().body(responseBody);
            }

            Date expirationDateRefreshToken = new Date(System.currentTimeMillis() + (expirationRefreshToken * 1000));
            String refreshToken = jwtUtil.generateToken(email, user.getRole(), expirationDateRefreshToken);

            Date expirationDateAccessToken = new Date(System.currentTimeMillis() + (expirationAccessToken * 1000));
            String accessToken = jwtUtil.generateToken(email, user.getRole(), expirationDateAccessToken);

            // Replace the existing access token with the new one
            user.setToken(refreshToken);
            userRepository.save(user);

            jwtUtil.setTokenInCookies(response, accessToken, nameAccessToken, expirationAccessToken);

            responseBody.put("message", "Login successful.");
            return ResponseEntity.status(HttpStatus.CREATED).body(responseBody);
        } catch (Exception e) {
            logger.error("An error occurred during login.", e);
            responseBody.put("error", "An error occurred during login.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseBody);
        }
    }
}
