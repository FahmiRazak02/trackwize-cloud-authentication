package com.trackwize.authentication.mapstruct;

import com.trackwize.authentication.model.dto.UserRegistrationReqDTO;
import com.trackwize.authentication.model.entity.User;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapStruct {

    User toEntity(UserRegistrationReqDTO reqDTO);
}
