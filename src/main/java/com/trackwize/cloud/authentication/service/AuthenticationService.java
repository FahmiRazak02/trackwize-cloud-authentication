package com.trackwize.cloud.authentication.service;

import com.trackwize.cloud.authentication.constant.ErrorConst;
import com.trackwize.cloud.authentication.exception.TrackWizeException;
import com.trackwize.cloud.authentication.mapper.UserMapper;
import com.trackwize.cloud.authentication.model.dto.AuthenticationReqDTO;
import com.trackwize.cloud.authentication.model.entity.User;
import com.trackwize.cloud.authentication.util.EncryptUtil;
import com.trackwize.cloud.authentication.util.JWTUtil;
import com.trackwize.cloud.authentication.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserMapper userMapper;
    private final JWTUtil jwtUtil;

    public String validateCredentials(AuthenticationReqDTO reqDTO) throws TrackWizeException {
        log.info("---------- validateCredentials() ----------");

        User user = userMapper.findByEmail(reqDTO.getEmail());
        if (user == null) {
            throw new TrackWizeException(
                    ErrorConst.NO_RECORD_FOUND_CODE,
                    ErrorConst.NO_RECORD_FOUND_MSG
            );
        }

        boolean isPasswordMatch = validatePassword(reqDTO, user);
        if (!isPasswordMatch) {
            throw new TrackWizeException(
                    ErrorConst.INVALID_CREDENTIALS_CODE,
                    ErrorConst.INVALID_CREDENTIALS_MSG
            );
        }

        String token = generateToken(user);
        if (token.isEmpty() || token == null) {
            throw new TrackWizeException(
                    ErrorConst.INTERNAL_SERVER_ERROR_CODE,
                    ErrorConst.INTERNAL_SERVER_ERROR_MSG
            );
        }

        return token;
    }

    private String generateToken(User user) {
        log.info("---------- generateToken() ----------");

        Map<String, Object> claims = new HashMap<>();
        claims.put("name", user.getName());
        claims.put("email", user.getEmail());

        return jwtUtil.generateToken(claims, user.getUserId(), "");
    }

    private boolean validatePassword(AuthenticationReqDTO reqDTO, User user) {
        log.info("---------- validatePassword() ----------");

        String encryptedPassword = EncryptUtil.decrypt(reqDTO.getEncryptedPassword(), reqDTO.getKey());
        return PasswordUtil.isPasswordMatch(encryptedPassword, user.getPassword());
    }
}
