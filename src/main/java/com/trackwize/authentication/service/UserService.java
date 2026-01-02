package com.trackwize.authentication.service;

import com.trackwize.common.constant.ErrorConst;
import com.trackwize.authentication.mapper.UserMapper;
import com.trackwize.authentication.model.dto.AuthenticationReqDTO;
import com.trackwize.authentication.model.entity.User;
import com.trackwize.common.exception.TrackWizeException;
import com.trackwize.common.util.EncryptUtil;
import com.trackwize.common.util.PasswordUtil;
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
        boolean isPasswordMatch = PasswordUtil.isPasswordMatch(reqDTO.getPassword(), user.getPassword());
        if (!isPasswordMatch) {
            throw new TrackWizeException(
                    ErrorConst.INVALID_CREDENTIALS_CODE,
                    ErrorConst.INVALID_CREDENTIALS_MSG
            );
        }

        return true;
    }

    public int create(User user) {
        return userMapper.create(user);
    }
}
