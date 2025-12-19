package com.trackwize.authentication.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ResetRequestDTO {

    private String token;
    private String encryptedPassword;
    private String key;
}
