package com.trackwize.authentication.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationReqDTO {

    private String email;
    private String password;
    private String contactNo;
    private String name;
}
