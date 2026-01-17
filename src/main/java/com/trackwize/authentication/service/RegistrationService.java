package com.trackwize.authentication.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.trackwize.authentication.mapstruct.UserMapStruct;
import com.trackwize.authentication.model.dto.UserRegistrationReqDTO;
import com.trackwize.authentication.model.entity.User;
import com.trackwize.common.constant.DBConst;
import com.trackwize.common.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationService {

    private final UserService userService;
    private final NotificationService notificationService;
    private final TokenService tokenService;

    private final UserMapStruct userMapStruct;

    public void submitUserRegistration(
            UserRegistrationReqDTO reqDTO,
            String trackingId
    ) throws JsonProcessingException {
        String encryptedPassword = PasswordUtil.encryptPassword(reqDTO.getPassword());

        User user = userMapStruct.toEntity(reqDTO);
        user.setPassword(encryptedPassword);
        user.setStatus(DBConst.STATUS_PENDING);

        userService.create(user);

        handleAccountVerification(user, reqDTO, trackingId);
    }

    private void handleAccountVerification(
            User user,
            UserRegistrationReqDTO reqDTO,
            String trackingId
    ) throws JsonProcessingException {
        String token = tokenService.generateEmailVerificationToken(reqDTO.getEmail());

        notificationService.sendAccountVerificationEmail(user.getEmail(), user.getName(), trackingId, token);
    }
}
