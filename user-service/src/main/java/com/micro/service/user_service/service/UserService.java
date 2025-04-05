package com.micro.service.user_service.service;

import com.micro.service.user_service.entity.User;
import com.micro.service.user_service.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public User registerUser(User user){
        return userRepository.save(user);
    }

    public List<User> findByUsername(String username){
        return userRepository.findByUsername(username);
    }

    public User findByEmail(String email) {
        return userRepository.findByEmail(email);  // 返回单个用户对象
    }
}
