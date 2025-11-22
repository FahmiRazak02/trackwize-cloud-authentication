package com.trackwize.cloud.authentication.service;

import com.trackwize.cloud.authentication.constant.ErrorConst;
import com.trackwize.cloud.authentication.exception.TrackWizeException;
import com.trackwize.cloud.authentication.mapper.UserMapper;
import com.trackwize.cloud.authentication.model.dto.AuthenticationReqDTO;
import com.trackwize.cloud.authentication.model.entity.User;
import com.trackwize.cloud.authentication.util.EncryptUtil;
import com.trackwize.cloud.authentication.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ObjectUtils;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserMapper userMapper;

    public User getUserByEmail(String email) {
        User user = userMapper.findByEmail(email);
        if (ObjectUtils.isEmpty(user)) {
            throw new TrackWizeException(
                    ErrorConst.NO_RECORD_FOUND_CODE,
                    ErrorConst.NO_RECORD_FOUND_MSG
            );
        }

        return user;
    }

    public boolean validatePassword(AuthenticationReqDTO reqDTO, User user) {
        String encryptedPassword = EncryptUtil.decrypt(reqDTO.getEncryptedPassword(), reqDTO.getKey());
        boolean isPasswordMatch = PasswordUtil.isPasswordMatch(encryptedPassword, user.getPassword());
        if (!isPasswordMatch) {
            throw new TrackWizeException(
                    ErrorConst.INVALID_CREDENTIALS_CODE,
                    ErrorConst.INVALID_CREDENTIALS_MSG
            );
        }

        return true;
    }
}
