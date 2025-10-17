package com.trackwize.cloud.authentication.model.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    private String userId;
    private String email;
    private String password;
    private String contactNumber;
    private String name;
    private String status;

    private String createdBy;
    private Instant createdDate;
    private String updatedBy;
    private Instant updatedDate;
}
