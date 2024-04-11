package com.user.authenticationAndAuthorisation.user.Controllers;

import com.user.authenticationAndAuthorisation.user.JwtUtil;
import com.user.authenticationAndAuthorisation.user.UserModel;
import com.user.authenticationAndAuthorisation.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("${api.users-url}")
@CrossOrigin("*")
public class ResetPassword {

    private static final Logger logger = LoggerFactory.getLogger(Register.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${nameAccessToken}")
    private String nameAccessToken;

    @PostMapping("/changePassword")
    public ResponseEntity<Map<String, Object>> changePassword(@RequestBody Map<String, String> requestBody, HttpServletRequest request) {
        Map<String, Object> responseBody = new HashMap<>();

        try {
            String token = jwtUtil.getTokenFromCookies(request, nameAccessToken);
            if (token == null) {
                responseBody.put("error", "You are not authenticated. Please log in again.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseBody);
            }

            String oldPassword = requestBody.get("oldPassword");
            String newPassword = requestBody.get("newPassword");

            if ( oldPassword == null || newPassword == null || oldPassword.isEmpty() || newPassword.isEmpty()) {
                responseBody.put("error", "password or newPassword must not be empty.");
                return ResponseEntity.badRequest().body(responseBody);
            }

            if ( newPassword.equals(oldPassword) ) {
                responseBody.put("error", "old password and new password  cannot be the same.");
                return ResponseEntity.badRequest().body(responseBody);
            }

            Map<String, Object> tokenData = jwtUtil.getDataFromToken(token);
            String email = (String) tokenData.get("email");

            Optional<UserModel> existingUser = userRepository.findByEmail(email);

            if (!existingUser.isPresent()) {
                responseBody.put("error", "User not found");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(responseBody);
            }

            UserModel user = existingUser.get();
            String userPassword = user.getPassword();

            // Compare the provided password with the stored hashed password
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            if (!passwordEncoder.matches(oldPassword, userPassword)) {
                responseBody.put("error", "Incorrect password.");
                return ResponseEntity.badRequest().body(responseBody);
            }

            user.setPassword(new BCryptPasswordEncoder().encode(newPassword));
            userRepository.save(user);

            responseBody.put("message", "Password reset successfully.");
            return ResponseEntity.status(HttpStatus.CREATED).body(responseBody);
        } catch (Exception e) {
            logger.error("An error occurred during reset password.", e);
            responseBody.put("error", "An error occurred during reset password..");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseBody);
        }
    }
}