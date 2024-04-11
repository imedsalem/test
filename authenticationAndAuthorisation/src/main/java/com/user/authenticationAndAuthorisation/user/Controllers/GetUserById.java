package com.user.authenticationAndAuthorisation.user.Controllers;

import com.user.authenticationAndAuthorisation.user.AuthorizationUtil;
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
public class GetUserById {

    private static final Logger logger = LoggerFactory.getLogger(Register.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${nameAccessToken}")
    private String nameAccessToken;

    /**
     * Retrieves user information by user ID.
     *
     * @param request The HTTPServletRequest containing the request information.
     * @param id      The ID of the user to retrieve.
     * @return A ResponseEntity containing user information or an error message.
     */

    @GetMapping("/getUserById/{id}")
    public ResponseEntity getUserById(HttpServletRequest request, @PathVariable Long id) {
        Map<String, Object> responseBody = new HashMap<>();

        try {
            String token = jwtUtil.getTokenFromCookies(request, nameAccessToken);
            if (token == null) {
                responseBody.put("error", "You are not authenticated. Please log in again.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseBody);
            }

            Optional<UserModel> user = userRepository.findById(id);
            if (!user.isPresent()) {
                responseBody.put("error", "User not found");
                return ResponseEntity.badRequest().body(responseBody);
            }

            // Create a map with only the desired fields
            Map<String, Object> userMap = new HashMap<>();
            userMap.put("username", user.get().getUserName());
            userMap.put("email", user.get().getEmail());
            userMap.put("status", user.get().getStatus());
            userMap.put("verify", user.get().isVerify());

            Map<String, Object> tokenData = jwtUtil.getDataFromToken(token);
            String role = (String) tokenData.get("role");

            if ("admin".equals(role)) return ResponseEntity.status(HttpStatus.CREATED).body(user);

            return ResponseEntity.status(HttpStatus.CREATED).body(userMap);
        } catch (Exception e) {
            logger.error("An error occurred during get user by id.", e);
            responseBody.put("error", "An error occurred during get user by id");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseBody);
        }
    }
}