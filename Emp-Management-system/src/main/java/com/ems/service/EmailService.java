package com.ems.service;

import java.util.List;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;


@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    @Async
    public void sendEmailToAdmins(List<String> adminEmails, String newUserFirstName) {
        if (adminEmails.isEmpty()) {
            return; // No admin emails found, skip sending email
        }

        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            String htmlContent = "<html><body style='font-family: Arial, sans-serif; color: #333;'>"
                    + "<p>Dear Admin,</p>"
                    + "<p>We hope this email finds you well.</p>"
                    + "<p>A new user, <strong>" + newUserFirstName + "</strong>, has recently registered on our platform.</p>"
                    + "<p>We kindly request you to review their registration details and approve their access accordingly.</p>"
                    + "<p>Please log in to the <a href='[ADMIN_PANEL_URL]' style='color: #007bff; text-decoration: none;'>Admin Panel</a> to complete the approval process.</p>"
                    + "<p>If you have any questions or require further information, please feel free to reach out.</p>"
                    + "<p style='margin-top: 20px;'>Best regards,<br><strong></hr></strong></p>"
                    + "</body></html>";

            helper.setTo(adminEmails.toArray(new String[0])); // Convert list to array
            helper.setSubject("Action Required: New User Registration Approval");
            helper.setText(htmlContent, true); // Enable HTML content

            mailSender.send(message);
        } catch (MessagingException e) {
            e.printStackTrace(); // Handle the exception properly (e.g., log it)
        }
    }

    // New method to send email to user when their account is activated
    
    @Async
    public void sendAccountActivationEmail(String userEmail, String userFirstName) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            String htmlContent = "<html><body style='font-family: Arial, sans-serif; color: #333;'>"
                    + "<p>Dear " + userFirstName + ",</p>"
                    + "<p>We are pleased to inform you that your account has been activated!</p>"
                    + "<p>You can now access all the services provided by our platform.</p>"
                    + "<p>If you have any questions or need assistance, feel free to reach out to us.</p>"
                    + "<p style='margin-top: 20px;'>Best regards,<br><strong>The Team EMS (Effigo !!)</strong></p>"
                    + "</body></html>";

            helper.setTo(userEmail);
            helper.setSubject("Your Account is Now Active");
            helper.setText(htmlContent, true); // Enable HTML content

            mailSender.send(message);
        } catch (MessagingException e) {
            e.printStackTrace(); // Handle the exception properly (e.g., log it)
        }
    }
}
