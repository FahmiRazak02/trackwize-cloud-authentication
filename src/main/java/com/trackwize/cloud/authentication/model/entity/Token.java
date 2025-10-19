package com.trackwize.cloud.authentication.model.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Token {

    private Long tokenId;
    private Long userId;
    private String accessToken;
    private String refreshToken;

    private String status;
    private Long createdBy;
    private Instant createdDate;
    private Long updatedBy;
    private Instant updatedDate;
}
