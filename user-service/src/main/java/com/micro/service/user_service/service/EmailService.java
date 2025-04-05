package com.micro.service.user_service.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    public void sendVerificationCode(String to, String code) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setSubject("【注册验证码】");
        message.setText("您的验证码是：" + code + "，有效期5分钟。请勿泄露给他人。");
        message.setTo(to);
        message.setFrom("2645779070@qq.com");

        mailSender.send(message);
    }
}
