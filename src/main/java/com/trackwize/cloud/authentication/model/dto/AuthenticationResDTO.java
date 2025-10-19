package com.trackwize.cloud.authentication.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResDTO {

    private String accessToken;
    private String refreshToken;
}
