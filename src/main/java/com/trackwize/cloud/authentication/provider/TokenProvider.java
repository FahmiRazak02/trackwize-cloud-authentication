package com.trackwize.cloud.authentication.provider;

import com.trackwize.cloud.authentication.constant.DBConst;
import com.trackwize.cloud.authentication.model.entity.Token;
import org.apache.ibatis.jdbc.SQL;

public class TokenProvider {

    public String findAll() {
        return new SQL()
                .FROM(DBConst.TOKEN_TABLE)
                .SELECT("*")
                .WHERE("status = " + DBConst.STATUS_ACTIVE)
                .toString();
    }

    public String isTokenExist(Long userId) {
        return new SQL()
                .SELECT("COUNT(1)")
                .FROM(DBConst.TOKEN_TABLE)
                .WHERE("user_id = #{userId}")
                .WHERE("status = " + DBConst.STATUS_ACTIVE)
                .toString();
    }

    public String createTokenRecord(Token token) {
        return new SQL()
                .INSERT_INTO(DBConst.TOKEN_TABLE)
                .VALUES("user_id", "#{userId}")
                .VALUES("access_token", "#{accessToken}")
                .VALUES("refresh_token", "#{refreshToken}")
                .VALUES("created_by", "#{createdBy}")
                .VALUES("created_date", "NOW()")
                .toString();
    }

    public String updateTokenRecord(Token token) {
        return new SQL()
                .UPDATE(DBConst.TOKEN_TABLE)
                .SET("access_token = #{accessToken}")
                .SET("refresh_token = #{refreshToken}")
                .SET("updated_by = #{updatedBy}")
                .SET("updated_date = NOW()")
                .toString();
    }

    public String findByUserId(Long userId) {
        return new SQL()
                .SELECT("*")
                .FROM(DBConst.TOKEN_TABLE)
                .WHERE("user_id = #{userId}")
                .WHERE("status = " + DBConst.STATUS_ACTIVE)
                .toString();
    }
}
