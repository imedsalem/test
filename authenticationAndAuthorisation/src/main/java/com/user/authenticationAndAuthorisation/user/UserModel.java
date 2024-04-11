package com.user.authenticationAndAuthorisation.user;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name="user")
public class UserModel {

    @Id
    @GeneratedValue()
    private Long id;
    private String userName;
    private String email;
    private String password;
    private String role;
    private boolean isVerify;
    private Integer verifyCode;
    private String status; //active, suspended, disabled, deleted
    private String statusDuration;
    private String token;
    private String created_at;
    private String updated_at;

}
