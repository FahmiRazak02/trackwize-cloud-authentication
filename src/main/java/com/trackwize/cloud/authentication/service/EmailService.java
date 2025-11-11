package com.trackwize.cloud.authentication.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trackwize.cloud.authentication.model.dto.NotificationReqDTO;
import com.trackwize.cloud.authentication.util.ActiveMQUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    @Value("${spring.artemis.queues.email}")
    private String emailQueue;

    private final ActiveMQUtil activeMQUtil;

    public void sendEmail(NotificationReqDTO reqDTO) throws JsonProcessingException {
        String correlationId = reqDTO.getTrackingId();

        ObjectMapper objectMapper = new ObjectMapper();
        String messageReq = objectMapper.writeValueAsString(reqDTO);

        activeMQUtil.send(correlationId, emailQueue, messageReq);
    }
}
