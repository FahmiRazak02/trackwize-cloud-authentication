package com.trackwize.cloud.authentication.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EncryptResDTO {

    private String encryptedPassword;
    private String key;
}
