package com.trackwize.authentication.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegistrationReqDTO {

    private Long userId;
    private String email;
    private String password;
    private String encryptedPassword;
    private String key;
    private String contactNo;


}
