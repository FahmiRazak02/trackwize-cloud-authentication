package com.trackwize.cloud.authentication.mapper;

import com.trackwize.cloud.authentication.model.entity.User;
import com.trackwize.cloud.authentication.provider.UserProvider;
import org.apache.ibatis.annotations.*;

import java.util.List;

@Mapper
public interface UserMapper {

    @SelectProvider(type = UserProvider.class, method = "findAll")
    @Results(id = "userMap", value = {
            @Result(property = "userId", column = "user_id"),
            @Result(property = "email", column = "email"),
            @Result(property = "password", column = "password"),
            @Result(property = "contactNumber", column = "contact_number"),
            @Result(property = "name", column = "name"),
            @Result(property = "status", column = "status"),
            @Result(property = "createdBy", column = "created_by"),
            @Result(property = "createdDate", column = "created_date"),
            @Result(property = "updatedBy", column = "updated_by"),
            @Result(property = "updatedDate", column = "updated_date")
    })
    List<User> findAll();

    @SelectProvider(type = UserProvider.class, method = "findByEmail")
    @ResultMap("userMap")
    User findByEmail(String email);

    @SelectProvider(type = UserProvider.class, method = "findById")
    @ResultMap("userMap")
    User findById(Long userId);
}
