package com.trackwize.cloud.authentication.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TokenReqDTO {

    private Long userId;
    private String accessToken;
    private String refreshToken;

    private Long createdBy;
    private Instant createdDate;
    private Long updatedBy;
    private Instant updatedDate;
}