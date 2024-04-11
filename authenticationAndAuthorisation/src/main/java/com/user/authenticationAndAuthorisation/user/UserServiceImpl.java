package com.user.authenticationAndAuthorisation.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Random;

@Service
public class UserServiceImpl implements UserService{

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JavaMailSender javaMailSender;
    @Override
    public UserModel registerUser(String userName, String email, String password) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String createdAt = LocalDateTime.now().format(formatter);

        UserModel newUser = new UserModel();
        Random random = new Random();
        newUser.setUserName(userName);
        newUser.setEmail(email);
        newUser.setPassword(new BCryptPasswordEncoder().encode(password));
        newUser.setRole("user");
        newUser.setVerifyCode(random.nextInt(900000) + 100000);;
        newUser.setVerify(false);
        newUser.setStatus("active");
        newUser.setCreated_at(createdAt);
        newUser.setUpdated_at(createdAt);

        return userRepository.save(newUser);
    }

    @Override
    public void sendEmail(String email, String subject, String text) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(email);
        message.setSubject(subject);
        message.setText(text);

        javaMailSender.send(message);

        System.out.println("Email sent successfully");
    }
}
