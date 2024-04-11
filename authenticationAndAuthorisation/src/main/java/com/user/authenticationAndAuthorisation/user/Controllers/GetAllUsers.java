package com.user.authenticationAndAuthorisation.user.Controllers;

import com.user.authenticationAndAuthorisation.user.JwtUtil;
import com.user.authenticationAndAuthorisation.user.UserModel;
import com.user.authenticationAndAuthorisation.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("${api.users-url}")
@CrossOrigin("*")
public class GetAllUsers {

    private static final Logger logger = LoggerFactory.getLogger(Register.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtil jwtUtil;

    @Value("${nameAccessToken}")
    private String nameAccessToken;

    /**
     * Retrieve a paginated list of users.
     *
     * @param search     A search string to filter users by role, email, or username (optional).
     * @param page       The page number for pagination (default is 0).
     * @param pageSize   The number of users per page (default is 10).
     * @param request    The HTTP servlet request.
     * @return           A ResponseEntity containing a JSON response with paginated user data.
     */

    @GetMapping("/getAllUsers")
    public ResponseEntity getAllUsers(
            @RequestParam(defaultValue = "") String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int pageSize,
            HttpServletRequest request
    ) {
        Map<String, Object> responseBody = new HashMap<>();
        try {

            String token = jwtUtil.getTokenFromCookies(request, nameAccessToken);
            if (token == null) {
                responseBody.put("error", "You are not authenticated. Please log in again.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(responseBody);
            }

            // Create a PageRequest with the given page and pageSize
            PageRequest pageRequest = PageRequest.of(page, pageSize);

            // Fetch users with pagination and search
            Page<UserModel> users;
            if (!search.isEmpty()) {
                users = userRepository.findByRoleContainingOrEmailContainingOrUserNameContaining(search, search, search, pageRequest);
                if (users.isEmpty()) {
                    responseBody.put("error", "item not found");
                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseBody);
                };
            } else {
                users = userRepository.findAll(pageRequest);
            }

            // Create a map with only the desired fields
            List<Map<String, Object>> userMaps = new ArrayList<>();

            for (UserModel user : users) {
                Map<String, Object> userMap = new HashMap<>();
                userMap.put("email", user.getEmail());
                userMap.put("status", user.getStatus());
                userMap.put("isVerify", user.isVerify());
                userMap.put("role", user.getRole());
                userMap.put("created_at", user.getCreated_at());
                userMap.put("updated_at", user.getUpdated_at());
                userMaps.add(userMap);
            }

            responseBody.put("usersPaginate", userMaps);
            responseBody.put("currentPage", users.getNumber());
            responseBody.put("totalItems", users.getTotalElements());
            responseBody.put("totalPages", users.getTotalPages());

            return ResponseEntity.status(HttpStatus.OK).body(responseBody);
        } catch (Exception e) {
            logger.error("An error occurred during get user by id.", e);
            responseBody.put("error", "An error occurred during get user by id");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(responseBody);
        }
    }


}