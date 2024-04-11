package com.user.authenticationAndAuthorisation.user.Controllers;

import com.user.authenticationAndAuthorisation.user.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("${api.users-url}")
@CrossOrigin("*")
public class NewAccessToken {

    private static final Logger logger = LoggerFactory.getLogger(Register.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AuthorizationUtil authorizationUtil;

    @Value("${expirationAccessToken}")
    private int expirationAccessToken;

    @Value("${nameAccessToken}")
    private String nameAccessToken;

    /**
     * Generates a new access token for an authenticated user.
     *
     * @param request  The HTTP request containing the user's cookies.
     * @param response The HTTP response to set the new access token as a cookie.
     * @return ResponseEntity with a success message if a new access token is created successfully,
     *         or an error message if an error occurs during the process.
     */

    @PostMapping("/newAccessToken")
    public ResponseEntity<Map<String, Object>> newAccessToken(HttpServletRequest request, HttpServletResponse response) {
        Map<String, Object> responseBody = new HashMap<>();

        try {
            String token = jwtUtil.getTokenFromCookies(request, nameAccessToken);
            if (token == null) {
                responseBody.put("error", "You are not authenticated. Please log in again.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseBody);
            }

            //Boolean roleValidResult = (Boolean) authorizationUtil.authorizationUtil("admin", token);  // Cast the result to Boolean

            //if (roleValidResult == null) {
            //    responseBody.put("error", "Please log in again or check your role permissions");
            //    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(responseBody);
            //}

            //if (!roleValidResult) {
            //    responseBody.put("error", "You are not authorized to perform this action.");
            //    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(responseBody);
            //}

            Map<String, Object> tokenData = jwtUtil.getDataFromToken(token);
            String email = (String) tokenData.get("email");

            Optional<UserModel> existingUser = userRepository.findByEmail(email);

            if (!existingUser.isPresent()) {
                responseBody.put("error", "User not found");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(responseBody);
            }

            UserModel user = existingUser.get();
            String userToken = user.getToken();

            boolean isValidUserToken = jwtUtil.isTokenValid(userToken);

            if (!isValidUserToken) {
                responseBody.put("error", "Please log in again");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseBody);
            }

            Date expirationDateAccessToken = new Date(System.currentTimeMillis() + (expirationAccessToken * 1000));
            String accessToken = jwtUtil.generateToken(email, user.getRole(), expirationDateAccessToken);

            jwtUtil.setTokenInCookies(response, accessToken, nameAccessToken, expirationAccessToken);

            responseBody.put("message", "Access token created successfully");
            return ResponseEntity.status(HttpStatus.CREATED).body(responseBody);
        } catch (Exception e) {
            logger.error("An error occurred during access token generation.", e);
            responseBody.put("error", "An error occurred during access token generation.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseBody);
        }
    }
}
