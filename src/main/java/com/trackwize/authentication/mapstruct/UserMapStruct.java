package com.trackwize.authentication.mapstruct;

import com.trackwize.authentication.model.dto.UserRegistrationReqDTO;
import com.trackwize.authentication.model.entity.User;
import com.trackwize.common.config.MapStructConfig;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring", config = MapStructConfig.class)
public interface UserMapStruct {

    User toEntity(UserRegistrationReqDTO reqDTO);
}
