package com.user.authenticationAndAuthorisation.user;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class AuthorizationUtil {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationUtil.class);

    @Autowired
    private JwtUtil jwtUtil;

    /**
     * Checks if the user associated with a given token has the specified role(s).
     *
     * @param roleToCheck The role(s) to check, separated by "OR".
     * @param token       The JWT token containing user information.
     * @return True if the user has one of the specified roles, false otherwise, or null in case of invalid input.
     */

    public Boolean authorizationUtil(String roleToCheck, String token) {
        Map<String, Object> tokenData = jwtUtil.getDataFromToken(token);
        String role = (String) tokenData.get("role");

        if (role == null || roleToCheck == null || roleToCheck.isEmpty()) {
            return null;
        }

        String[] rolesToCheck = roleToCheck.split("OR");

        for (String roleToCompare : rolesToCheck) {
            if (role.equals(roleToCompare.trim())) {
                return true;
            }
        }
        return false;
    }
}
