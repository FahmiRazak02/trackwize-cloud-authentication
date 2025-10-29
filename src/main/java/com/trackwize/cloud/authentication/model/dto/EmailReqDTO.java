package com.trackwize.cloud.authentication.model.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class EmailReqDTO {

    private String recipient;
    private String subject;
    private Map<String, Object> contents;
}
