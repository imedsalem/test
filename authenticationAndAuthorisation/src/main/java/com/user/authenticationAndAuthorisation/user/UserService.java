package com.user.authenticationAndAuthorisation.user;

public interface UserService {

    UserModel registerUser(String userName, String email, String password);

    void sendEmail(String email, String subject, String text);
}
