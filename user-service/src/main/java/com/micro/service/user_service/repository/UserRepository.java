package com.micro.service.user_service.repository;

import com.micro.service.user_service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface UserRepository extends JpaRepository<User,Long> {
    List<User> findByUsername(String username);
    User findByEmail(String email);
}
