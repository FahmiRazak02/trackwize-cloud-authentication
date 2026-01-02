package com.trackwize.authentication.model.dto;

import com.trackwize.common.constant.CommonConst;
import com.trackwize.common.validation.PasswordMatch;
import com.trackwize.common.validation.PasswordValidator;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@PasswordValidator
@NoArgsConstructor
@AllArgsConstructor
public class ResetRequestDTO {

    @NotBlank(message = "password is required")
    private String password;

    @NotBlank(message = "confirm password is required")
    private String confirmPassword;
}
