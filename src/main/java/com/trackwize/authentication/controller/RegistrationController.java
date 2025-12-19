package com.trackwize.authentication.controller;

import com.trackwize.authentication.model.dto.UserRegistrationReqDTO;
import com.trackwize.authentication.service.RegistrationService;
import com.trackwize.common.constant.ErrorConst;
import com.trackwize.common.exception.TrackWizeException;
import com.trackwize.common.util.ResponseUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/vi/reg")
@RequiredArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;

    @PostMapping("/submit")
    public ResponseUtil submitUserRegistration(
            @RequestBody UserRegistrationReqDTO reqDTO
    ) {
        ResponseUtil responseUtil = ResponseUtil.success();

        String isValid = registrationService.validateRegistrationReq(reqDTO);
        if (StringUtils.isNotBlank(isValid)){
            throw new TrackWizeException(
                    ErrorConst.MISSING_REQUIRED_INPUT_CODE,
                    isValid
            );
        }

        registrationService.submitUserRegsistration(reqDTO);
        return responseUtil;
    }
}
