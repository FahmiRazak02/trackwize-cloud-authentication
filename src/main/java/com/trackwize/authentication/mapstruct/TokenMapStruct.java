package com.trackwize.authentication.mapstruct;

import com.trackwize.authentication.model.dto.TokenReqDTO;
import com.trackwize.authentication.model.entity.Token;
import com.trackwize.common.config.MapStructConfig;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring", config = MapStructConfig.class)
public interface TokenMapStruct {

    Token toEntity(TokenReqDTO reqDTO);
}
