package com.user.authenticationAndAuthorisation.user.Controllers;

import com.user.authenticationAndAuthorisation.user.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("${api.users-url}")
@CrossOrigin("*")
public class LogOut {

    private static final Logger logger = LoggerFactory.getLogger(Register.class);

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${nameAccessToken}")
    private String nameAccessToken;

    /**
     * Logs out a user by deleting the access token cookie.
     *
     * @param response The HTTP response to delete the access token cookie.
     * @return ResponseEntity with a success message if the user is successfully logged out,
     *         or an error message if an error occurs during the logout process.
     */

    @PostMapping("/logout")
    public ResponseEntity logout(HttpServletResponse response) {
        Map<String, Object> responseBody = new HashMap<>();

        try {

            jwtUtil.setTokenInCookies(response, null, nameAccessToken, 0);

            responseBody.put("message", "Logged out successfully");
            return ResponseEntity.status(HttpStatus.CREATED).body(responseBody);
        } catch (Exception e) {
            logger.error("An error occurred during login.", e);
            responseBody.put("error", "An error occurred during login.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseBody);
        }
    }
}