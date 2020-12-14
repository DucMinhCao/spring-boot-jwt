package com.minhduc.jwt.constant;

public class SecurityConstants {
    public static final String HEADER_STRING = "Authorization";
    private static final String SECRET_STRING = "SECRET";
    public static final long EXPIRATION_TIME = 864000000;

    public static String getTokenSecret() {
        return SECRET_STRING;
    }
}
