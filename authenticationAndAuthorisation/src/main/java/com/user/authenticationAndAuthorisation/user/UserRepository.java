package com.user.authenticationAndAuthorisation.user;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.querydsl.QPageRequest;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserModel, Long> {

    Optional<UserModel> findByUserName(String userName);

    Optional<UserModel> findByEmail(String email);

    Page<UserModel> findByRoleContainingOrEmailContainingOrUserNameContaining(String role, String email , String userName ,Pageable pageable);


}
