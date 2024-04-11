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
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("${api.users-url}")
@CrossOrigin("*")
public class GetUserByToken {

    private static final Logger logger = LoggerFactory.getLogger(Register.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${nameAccessToken}")
    private String nameAccessToken;

    /**
     * Retrieves user information by token.
     *
     * @param request The HTTPServletRequest containing the request information.
     * @return A ResponseEntity containing user information or an error message.
     */

    @GetMapping("/getUserByToken")
    public ResponseEntity getUserByToken(HttpServletRequest request) {
        Map<String, Object> responseBody = new HashMap<>();

        try {
            String token = jwtUtil.getTokenFromCookies(request, nameAccessToken);
            if (token == null) {
                responseBody.put("error", "You are not authenticated. Please log in again.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseBody);
            }

            Map<String, Object> tokenData = jwtUtil.getDataFromToken(token);
            String email = (String) tokenData.get("email");

            Optional<UserModel> user = userRepository.findByEmail(email);

            // Create a map with only the desired fields
            Map<String, Object> userMap = new HashMap<>();
            userMap.put("username", user.get().getUserName());
            userMap.put("email", user.get().getEmail());
            userMap.put("status", user.get().getStatus());
            userMap.put("isVerify", user.get().isVerify());
            userMap.put("role", user.get().getRole());
            userMap.put("created_at", user.get().getCreated_at());
            userMap.put("updated_at", user.get().getUpdated_at());

            return ResponseEntity.status(HttpStatus.CREATED).body(userMap);
        } catch (Exception e) {
            logger.error("An error occurred during get user by Token.", e);
            responseBody.put("error", "An error occurred during get user by Token");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseBody);
        }
    }
}