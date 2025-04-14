package com.micro.service.user_service.controller;

import com.micro.service.user_service.config.JwtUtil;
import com.micro.service.user_service.entity.User;
import com.micro.service.user_service.service.EmailService;
import com.micro.service.user_service.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;
import java.util.UUID;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/sendCode")
    public String sendVerificationCode(@RequestParam String email) {
        String code = String.valueOf(new Random().nextInt(1000000) + 100000);

        redisTemplate.opsForValue().set("register:" + email, code, Duration.ofMinutes(5));

        emailService.sendVerificationCode(email, code);

        return "Verification code sent";
    }

    @PostMapping("/verifyCode")
    public ResponseEntity<String>  verifyCode(@RequestParam String email, @RequestParam String code) {
        String storedCode = (String) redisTemplate.opsForValue().get("register:" + email);

        if (storedCode == null) {
            return new ResponseEntity<>("Verification code expired", HttpStatus.GONE);//410 Gone
        }

        if (!storedCode.equals(code)) {
            return new ResponseEntity<>("Invalid verification code", HttpStatus.BAD_REQUEST); // 400 Bad Request
        }

        return new ResponseEntity<>("Verification successful", HttpStatus.OK); // 200 OK
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User user, @RequestParam String code) {
        // 调用验证码验证
        ResponseEntity<String> verificationResponse = verifyCode(user.getEmail(), code);

        // 如果验证码验证失败，返回相应的错误信息和状态码
        if (!verificationResponse.getStatusCode().equals(HttpStatus.OK)) {
            return verificationResponse; // 如果验证码无效，直接返回相应的错误响应
        }

        // 默认用户名
        if (user.getUsername() == null || user.getUsername().isEmpty()) {
            user.setUsername("user" + UUID.randomUUID().toString().substring(0, 8));
        }

        // 加密密码
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);

        // 设置默认角色
        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("coach");
        }

        // 默认头像
        if (user.getAvatar() == null) {
            user.setAvatar(""); // 或者默认一个头像URL
        }

        // 注册时间
        user.setCreatedAt(LocalDateTime.now());

        // 调用注册服务
        userService.registerUser(user);

        // 返回成功响应
        return new ResponseEntity<>("Registration successful", HttpStatus.OK); // 200 OK
    }

    @PostMapping("/login")
    public String login(@RequestParam String email, @RequestParam String password) {
        User user = userService.findByEmail(email);

        if (user == null) {
            return "Email not found";
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            return "Incorrect password";
        }

        String token = JwtUtil.generateToken(user.getEmail(), user.getRole());
        return token;
    }

    @GetMapping("/{username}")
    public List<User> getUserByUsername(@PathVariable String username){
        return userService.findByUsername(username);
    }

    @GetMapping("/test-auth")
    public String testAuth() {
        String username = (String) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return "Authenticated as: " + username;
    }

    @GetMapping("/player/test")
    public String playerOnly() {
        return "only player";
    }

    @GetMapping("/admin/test")
    public String adminOnly() {
        return "only admin";
    }

    @GetMapping("/coach/test")
    public String coachOnly() {
        return "only coach";
    }
}
