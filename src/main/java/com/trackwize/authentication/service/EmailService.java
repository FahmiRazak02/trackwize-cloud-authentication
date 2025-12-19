package com.trackwize.authentication.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.trackwize.authentication.model.dto.NotificationReqDTO;
import com.trackwize.common.util.ActiveMQUtil;
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
}
