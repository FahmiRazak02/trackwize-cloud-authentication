package com.trackwize.authentication.mapstruct;

import com.trackwize.authentication.model.dto.TokenReqDTO;
import com.trackwize.authentication.model.entity.Token;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface TokenMapStruct {

    Token toEntity(TokenReqDTO reqDTO);
}
