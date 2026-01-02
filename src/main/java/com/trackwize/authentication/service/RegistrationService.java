package com.trackwize.authentication.service;

import com.trackwize.authentication.mapstruct.UserMapStruct;
import com.trackwize.authentication.model.dto.UserRegistrationReqDTO;
import com.trackwize.authentication.model.entity.User;
import com.trackwize.common.constant.CommonConst;
import com.trackwize.common.util.PasswordUtil;
import com.trackwize.common.util.PasswordValidatorUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationService {

    private final UserService userService;
    private final UserMapStruct userMapStruct;

    public void submitUserRegistration(UserRegistrationReqDTO reqDTO) {
        String encryptedPassword = PasswordUtil.encryptPassword(reqDTO.getPassword());

        User user = userMapStruct.toEntity(reqDTO);
        user.setPassword(encryptedPassword);

        int createResult = userService.create(user);

    }
}
