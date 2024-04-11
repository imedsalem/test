package com.user.authenticationAndAuthorisation.user;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    @Autowired
    private HttpServletRequest request;

    @Value("${jwt.secret}")
    private String secretKey;

    /**
     * Generate a JWT token with the specified email, role, and expiration date.
     *
     * @param email          The email to be set as the subject of the token.
     * @param role           The user's role to be included in the token.
     * @param expirationDate The expiration date of the token.
     * @return The generated JWT token.
     */
    public String generateToken(String email, String role, Date expirationDate) {
        Date now = new Date();

        return Jwts.builder()
                .setSubject(email)
                .claim("role", role) // Add the role as a claim
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    /**
     * Check if a JWT token is valid and not expired by attempting to parse it.
     *
     * @param token The JWT token to validate.
     * @return true if the token is valid and not expired, false otherwise.
     */
    public boolean isTokenValid(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token)
                    .getBody();

            // Check if the token is expired
            Date expirationDate = claims.getExpiration();
            Date now = new Date();
            return !expirationDate.before(now);
        } catch (Exception e) {
            logger.error("Token validation failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Extracts data (including email and role) from a JWT token.
     *
     * @param token The JWT token from which to extract data.
     * @return A map containing the extracted data, where keys are "email" and "role,"
     *         or null if there was an error parsing the token.
     */
    public Map<String, Object> getDataFromToken(String token) {
        try {
            // Parse the JWT token and retrieve its claims
            Jws<Claims> claims = Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);

            // Extract email and role from the claims
            String email = claims.getBody().getSubject();
            String role = (String) claims.getBody().get("role");

            // Create a map to store the extracted data
            Map<String, Object> data = new HashMap<>();
            data.put("email", email);
            data.put("role", role);

            return data;
        } catch (Exception e) {
            logger.error("Error parsing JWT token", e);
            return null;
        }
    }

    /**
     * Sets a JWT token in a cookie with the specified name and max age.
     *
     * @param response     The HTTP servlet response.
     * @param token        The JWT token to set in the cookie.
     * @param cookieName   The name of the cookie to use.
     * @param cookieMaxAge The maximum age of the cookie in seconds.
     */
    public void setTokenInCookies(HttpServletResponse response, String token, String cookieName, int cookieMaxAge) {
        Cookie cookie = new Cookie(cookieName, token);
        cookie.setPath("/");
        cookie.setMaxAge(cookieMaxAge);
        response.addCookie(cookie);
    }

    /**
     * Gets a JWT token from cookies in the HTTP request.
     *
     * @param request The HTTP servlet request.
     * @param cookieName   The name of the cookie to use.
     * @return The JWT token from cookies, or null if not found.
     */
    public String getTokenFromCookies(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(cookieName)) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
