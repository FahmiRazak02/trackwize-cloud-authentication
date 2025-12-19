package com.trackwize.authentication.service;

import com.trackwize.authentication.mapstruct.UserMapStruct;
import com.trackwize.authentication.model.dto.UserRegistrationReqDTO;
import com.trackwize.authentication.model.entity.User;
import com.trackwize.common.constant.CommonConst;
import com.trackwize.common.util.PasswordUtil;
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

    public String validateRegistrationReq(UserRegistrationReqDTO reqDTO) {
        String errorBaseMsg = " is required.";
        String errorInvalidMsg = " is invalid";

        if (StringUtils.isBlank(reqDTO.getEmail()))
            return "Email "  + errorBaseMsg;

        if (isEmailValid(reqDTO.getEmail()))
            return "Email " + errorInvalidMsg;

        if (StringUtils.isBlank(reqDTO.getPassword()))
            return "Password " + errorBaseMsg;
        
        if (StringUtils.isNotBlank(isPasswordValid(reqDTO.getPassword())))
            return "Password" + errorInvalidMsg;
            
        if (StringUtils.isBlank(reqDTO.getContactNo()))
            return "Contact No " + errorBaseMsg;

        if (StringUtils.isBlank(reqDTO.getName()))
            return "Name " + errorBaseMsg;

        return null;
    }

    private String isPasswordValid(String password) {
        if (password.length() < CommonConst.PASSWORD_MIN_LENGTH)
            return "Password must be at least 8 characters long";

        if (!password.matches(CommonConst.PASSWORD_UPPERCASE_CHAR_REGEX))
            return "Password must contain at least one uppercase letter";

        if (!password.matches(CommonConst.PASSWORD_LOWERCASE_CHAR_REGEX))
            return "Password must contain at least one lowercase letter";

        if (!password.matches(CommonConst.PASSWORD_DIGIT_REGEX))
            return "Password must contain at least one number";

        if (!password.matches(CommonConst.PASSWORD_SPECIAL_CHAR_REGEX))
            return "Password must contain at least one special character";

        if (password.contains(" "))
            return "Password must not contain whitespace";

        return null;
    }

    private boolean isEmailValid(String email) {
        return email.matches(CommonConst.EMAIL_REGEX);
    }

    public void submitUserRegsistration(UserRegistrationReqDTO reqDTO) {
        String encryptedPassword = PasswordUtil.encryptPassword(reqDTO.getPassword());

        User user = userMapStruct.toEntity(reqDTO);
        user.setPassword(encryptedPassword);

        int createResult = userService.create(user);

    }
}
