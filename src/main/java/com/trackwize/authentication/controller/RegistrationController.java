package com.trackwize.authentication.controller;

import com.trackwize.authentication.model.dto.UserRegistrationReqDTO;
import com.trackwize.authentication.service.RegistrationService;
import com.trackwize.common.util.ResponseUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/v1/reg")
@RequiredArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;

    @PostMapping("/submit")
    public ResponseUtil submitUserRegistration(
            @RequestBody @Valid UserRegistrationReqDTO reqDTO
    ) {
        ResponseUtil responseUtil = ResponseUtil.success();

        registrationService.submitUserRegistration(reqDTO);
        return responseUtil;
    }
}
