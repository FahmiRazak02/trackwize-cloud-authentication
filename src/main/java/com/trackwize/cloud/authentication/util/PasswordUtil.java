package com.trackwize.cloud.authentication.util;

import org.springframework.security.crypto.bcrypt.BCrypt;

public class PasswordUtil {

    public static String encryptPassword(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt(12));
    }

    public static boolean isPasswordMatch(String reqPassword, String dbPassword) {
        return BCrypt.checkpw(reqPassword, dbPassword);
    }
}
