package com.trackwize.authentication.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trackwize.authentication.model.dto.NotificationReqDTO;
import com.trackwize.common.constant.NotificationConst;
import com.trackwize.common.constant.TokenConst;
import com.trackwize.common.util.ActiveMQUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class NotificationService {

    @Value("${spring.artemis.queues.email}")
    private String emailQueue;

    private final ActiveMQUtil activeMQUtil;

    /**
     * Send email notification by pushing message to ActiveMQ email queue.
     *
     * @param reqDTO The notification request data transfer object containing email details.
     * @throws JsonProcessingException If there is an error during JSON processing.
     */
    public void sendEmail(NotificationReqDTO reqDTO) throws JsonProcessingException {
        String correlationId = reqDTO.getTrackingId();

        ObjectMapper objectMapper = new ObjectMapper();
        String messageReq = objectMapper.writeValueAsString(reqDTO);

        activeMQUtil.send(correlationId, emailQueue, messageReq);
    }

    public void sendPasswordResetEmail(String email, String token, String trackingId) throws JsonProcessingException {
//        1. Build the email request payload and attach tracking ID
        var reqDTO = buildPassResetEmailReqDTO(email, token);
        reqDTO.setTrackingId(trackingId);

//        2. Send reset password email
        sendEmail(reqDTO);
    }

    /**
     * Build the email request DTO for password reset.
     *
     * @param email The recipient email address.
     * @param token The password reset token.
     * @return The constructed NotificationReqDTO.
     */
    private NotificationReqDTO buildPassResetEmailReqDTO(String email, String token) {
        var reqDTO = new NotificationReqDTO();
        reqDTO.setNotificationType(NotificationConst.EMAIL_NTF_TYPE);
        reqDTO.setTemplate(NotificationConst.PASSWORD_RESET_TEMPLATE);
        reqDTO.setRecipient(email);
        reqDTO.setSubject("TrackWize Password Reset");

        Map<String, Object> contents = new HashMap<>();
        contents.put("title", "TrackWize Password Reset Request");
        contents.put("message", "Click the link below to reset your password:");
        contents.put("token", token);
        contents.put("expiry", TokenConst.RESET_PASSWORD_TOKEN_EXPIRY);

        reqDTO.setContents(contents);
        return reqDTO;
    }

    public void sendRegistrationResultEmail(String email, String name,  String trackingId) throws JsonProcessingException {
        var reqDTO = buildRegResultReqDTO(email, name);
        reqDTO.setTrackingId(trackingId);

        sendEmail(reqDTO);
    }

    private NotificationReqDTO buildRegResultReqDTO(String email, String name) {
        var reqDTO = new NotificationReqDTO();
        reqDTO.setNotificationType(NotificationConst.EMAIL_NTF_TYPE);
        reqDTO.setTemplate(NotificationConst.REGISTRATION_RESULT_TEMPLATE);
        reqDTO.setRecipient(email);
        reqDTO.setSubject("Trackwize Account");

        Map<String, Object> contents = new HashMap<>();
        contents.put("Title", "Trackwize Account Registration");
        contents.put("message", "Your Trackwize Account is Created Successfully");
        contents.put("name", name);

        reqDTO.setContents(contents);
        return reqDTO;
    }

    public void sendAccountVerificationEmail(String email, String name, String token, String trackingId) throws JsonProcessingException {
        var reqDTO = buildAccVerificationReqDTO(email, name, token);
        reqDTO.setTrackingId(trackingId);

        sendEmail(reqDTO);
    }

    private NotificationReqDTO buildAccVerificationReqDTO(String email, String name, String token) {
        var reqDTO = new NotificationReqDTO();
        reqDTO.setNotificationType(NotificationConst.EMAIL_NTF_TYPE);
        reqDTO.setTemplate(NotificationConst.ACCOUNT_VERIFICATION_TEMPLATE);
        reqDTO.setRecipient(email);
        reqDTO.setSubject("Trackwize Account");

        Map<String, Object> contents = new HashMap<>();
        contents.put("Title", "Trackwize Account Verification");
        contents.put("message", "Please Verify Your Account");
        contents.put("name", name);
        contents.put("token", token);
        contents.put("expiry", TokenConst.ACCOUNT_VERIFICATION_TOKEN_EXPIRY);

        reqDTO.setContents(contents);
        return reqDTO;
    }
}
