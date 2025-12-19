package com.trackwize.authentication.model.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class User {

    private Long userId;
    private String email;
    private String password;
    private String contactNumber;
    private String name;

    private String status;
    private Long createdBy;
    private Instant createdDate;
    private Long updatedBy;
    private Instant updatedDate;
}
