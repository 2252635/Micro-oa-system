package com.micro.service.user_service.controller;

import com.micro.service.user_service.entity.User;
import com.micro.service.user_service.service.EmailService;
import com.micro.service.user_service.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
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
        System.out.println("收到邮箱: [" + email + "]");
        String code = String.valueOf(new Random().nextInt(1000000) + 100000);

        redisTemplate.opsForValue().set("register:" + email, code, Duration.ofMinutes(5));

        emailService.sendVerificationCode(email, code);

        return "验证码已发送";
    }

    @PostMapping("/verifyCode")
    public String verifyCode(@RequestParam String email, @RequestParam String code) {
        String storedCode = (String) redisTemplate.opsForValue().get("register:" + email);

        if (storedCode == null) {
            return "验证码已过期";
        }

        if (!storedCode.equals(code)) {
            return "验证码错误";
        }

        return "验证码正确";
    }

    @PostMapping("/register")
    public String register(@RequestBody User user, @RequestParam String code) {
        String verificationResult = verifyCode(user.getEmail(), code);
        if (!"验证码正确".equals(verificationResult)) {
            return verificationResult;
        }

        if (user.getUsername() == null || user.getUsername().isEmpty()) {
            user.setUsername("user" + UUID.randomUUID().toString().substring(0, 8));
        }

        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);

        userService.registerUser(user);

        return "注册成功";
    }

    @PostMapping("/login")
    public String login(@RequestParam String email, @RequestParam String password) {
        User user = userService.findByEmail(email);

        if (user == null) {
            return "邮箱不存在";
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            return "密码错误";
        }
        // 如果密码正确，可以在此生成一个 JWT 或 Session Token
        // 例如，如果使用 JWT，可以通过如下代码生成并返回一个 token：
        // String token = jwtService.generateToken(user);

        return "登录成功"; // 这里可以返回 JWT token 或会话信息
    }

    @GetMapping("/{username}")
    public List<User> getUserByUsername(@PathVariable String username){
        return userService.findByUsername(username);
    }
}
