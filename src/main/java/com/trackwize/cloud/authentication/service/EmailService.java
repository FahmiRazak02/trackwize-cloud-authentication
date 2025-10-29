package com.trackwize.cloud.authentication.service;

import com.trackwize.cloud.authentication.model.dto.EmailReqDTO;
import jakarta.mail.*;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Properties;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    @Value("${smtp.port}")
    private String smtpPort;

    @Value("${smtp.host}")
    private String smtpHost;

    @Value("${smtp.username}")
    private String smtpUsername;

    @Value("${smtp.password}")
    private String smtpPassword;

    public void sendEmail(EmailReqDTO reqDTO) throws MessagingException {

        Properties properties = new Properties();
        properties.put("mail.smtp.auth", true);
        properties.put("mail.smtp.starttls.enable", "true");
        properties.put("mail.smtp.host", smtpHost);
        properties.put("mail.smtp.port", smtpPort);
        properties.put("mail.smtp.ssl.trust", smtpHost);

        Session session = Session.getInstance(properties, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(smtpUsername, smtpPassword);
            }
        });

        MimeMessage message = new MimeMessage(session);
        message.setFrom(new InternetAddress(smtpUsername));
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(reqDTO.getRecipient()));
        message.setSubject(reqDTO.getSubject());

        MimeBodyPart mimeBodyPart = new MimeBodyPart();
        mimeBodyPart.setContent(contentsToHtml(reqDTO.getContents()), "text/html; charset=utf-8");

        Multipart multipart = new MimeMultipart();
        multipart.addBodyPart(mimeBodyPart);
        message.setContent(multipart);

        Transport.send(message);
    }

    public String contentsToHtml(Map<String, Object> contents) {
        if (contents == null || contents.isEmpty()) {
            return "";
        }

        String title = (String) contents.getOrDefault("title", "Notification");
        String message = (String) contents.getOrDefault("message", "Please review the details below.");
        String link = (String) contents.get("link");
        String expiry = String.valueOf(contents.getOrDefault("expiry", "10"));

        StringBuilder sb = new StringBuilder();
        sb.append("<html><body>")
                .append("<h3>").append(title).append("</h3>")
                .append("<p>").append(message).append("</p>");

        if (link != null && !link.isEmpty()) {
            sb.append("<p><a href=\"").append(link).append("\">Reset Password</a></p>");
        }

        sb.append("<br><p>This link will expire in ").append(expiry).append(" minutes.</p>")
                .append("</body></html>");

        return sb.toString();
    }
}
