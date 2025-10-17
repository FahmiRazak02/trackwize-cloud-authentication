package com.trackwize.cloud.authentication.constant;

public class ErrorConst {

//    GENERAL ERROR CODE - 10001 to 19999

    public static final String GENERAL_ERROR_CODE = "10001";
    public static final String GENERAL_ERROR_MSG = "Error has occurred, please try again.";

    public static final String INVALID_INPUT_CODE = "10002";
    public static final String INVALID_INPUT_MSG = "Invalid input";

    public static final String INTERNAL_SERVER_ERROR_CODE = "10003";
    public static final String INTERNAL_SERVER_ERROR_MSG = "Internal server error";

    public static final String SQL_ERROR_CODE = "10004";
    public static final String SQL_ERROR_MSG = "Database error occurred";

    public static final String NOT_FOUND_ERROR_CODE = "10005";
    public static final String NOT_FOUND_ERROR_MSG = "Requested resource not found";

    public static final String NO_RECORD_FOUND_CODE = "10006";
    public static final String NO_RECORD_FOUND_MSG = "No Record found.";

    public static final String MISSING_REQUIRED_INPUT_CODE = "10007";
    public static final String MISSING_REQUIRED_INPUT_MSG = "Missing required input: ";


//    AUTHENTICATION ERROR CODE - 20001 to 29999

    public static final String AUTHENTICATION_ERROR_CODE = "20001";
    public static final String AUTHENTICATION_ERROR_MSG = "Authentication error";

    public static final String INVALID_CREDENTIALS_CODE = "20002";
    public static final String INVALID_CREDENTIALS_MSG = "Invalid credentials";

    public static final String UNAUTHORIZED_ACCESS_CODE = "20003";
    public static final String UNAUTHORIZED_ACCESS_MSG = "Unauthorized access";

    public static final String TOKEN_EXPIRED_CODE = "20004";
    public static final String TOKEN_EXPIRED_MSG = "Token has expired";

    public static final String ACCOUNT_LOCKED_CODE = "20005";
    public static final String ACCOUNT_LOCKED_MSG = "Account is locked";

    public static final String INSUFFICIENT_PERMISSIONS_CODE = "20006";
    public static final String INSUFFICIENT_PERMISSIONS_MSG = "Insufficient permissions";

    public static final String SESSION_EXPIRED_CODE = "20007";
    public static final String SESSION_EXPIRED_MSG = "Session has expired";
}
