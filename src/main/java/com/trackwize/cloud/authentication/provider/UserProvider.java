package com.trackwize.cloud.authentication.provider;

import com.trackwize.cloud.authentication.constant.DBConst;
import org.apache.ibatis.jdbc.SQL;

public class UserProvider {



    public String findAll() {
        return new SQL()
                .SELECT("*")
                .FROM(DBConst.USER_TABLE)
                .WHERE("status = " + DBConst.STATUS_ACTIVE)
                .toString();
    }

    public String findByEmail(String email) {
        return new SQL()
                .SELECT("*")
                .FROM(DBConst.USER_TABLE)
                .WHERE("email = #{email}")
                .WHERE("status = " + DBConst.STATUS_ACTIVE)
                .toString();
    }

    public String findById(Long userId) {
        return new SQL()
                .SELECT("*")
                .FROM(DBConst.USER_TABLE)
                .WHERE("user_id = #{userId}")
                .WHERE("status = " + DBConst.STATUS_ACTIVE)
                .toString();
    }
}
