package com.trackwize.cloud.authentication.provider;

import org.apache.ibatis.jdbc.SQL;

public class UserProvider {

    public static final String USER_TABLE = "users";

    public String findAll() {
        return new SQL()
                .SELECT("*")
                .FROM(USER_TABLE)
                .toString();
    }

    public String findByEmail(String email) {
        return new SQL()
                .SELECT("*")
                .FROM(USER_TABLE)
                .WHERE("email = #{email}")
                .toString();
    }
}
