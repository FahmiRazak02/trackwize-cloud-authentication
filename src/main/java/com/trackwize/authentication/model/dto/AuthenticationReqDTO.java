package com.trackwize.authentication.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationReqDTO {

    private String email;
    private String encryptedPassword;
    private String key;
}
