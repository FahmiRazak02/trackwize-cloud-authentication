package com.trackwize.cloud.authentication.mapper;

import com.trackwize.cloud.authentication.model.entity.Token;
import com.trackwize.cloud.authentication.provider.TokenProvider;
import org.apache.ibatis.annotations.*;

import java.util.List;

@Mapper
public interface TokenMapper {

    @SelectProvider(type = TokenProvider.class, method = "findAll")
    @Results(id = "tokenMap", value = {
            @Result(property = "tokenId", column = "token_id"),
            @Result(property = "userId", column = "user_id"),
            @Result(property = "accessToken", column = "access_token"),
            @Result(property = "refreshToken", column = "refresh_token"),
            @Result(property = "status", column = "status"),
            @Result(property = "createdBy", column = "created_by"),
            @Result(property = "createdDate", column = "created_date"),
            @Result(property = "updatedBy", column = "updated_by"),
            @Result(property = "updatedDate", column = "updated_date"),
    })
    List<Token> findAll();

    @SelectProvider(type = TokenProvider.class, method = "isTokenExist")
    boolean isExist(Long userId);

    @InsertProvider(type = TokenProvider.class, method = "createTokenRecord")
    int create(Token token);

    @UpdateProvider(type = TokenProvider.class, method = "updateTokenRecord")
    int update(Token token);

    @SelectProvider(type = TokenProvider.class, method = "findByUserId")
    Token findByUserId(String userId);
}
