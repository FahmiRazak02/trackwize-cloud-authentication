package com.trackwize.cloud.authentication.mapstruct;

import com.trackwize.cloud.authentication.model.dto.TokenReqDTO;
import com.trackwize.cloud.authentication.model.entity.Token;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface TokenMapStruct {

    Token toEntity(TokenReqDTO reqDTO);
}
