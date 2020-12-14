package com.minhduc.jwt.shared.utils;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;

@Service
public class Util {

    private static String RANDOM_STRING = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static SecureRandom RANDOM = new SecureRandom();

    public String generateUserId(int length) {
        return generateRandomString(length);
    }

    private String generateRandomString(int length) {
        StringBuilder res = new StringBuilder();

        for (int i = 0; i < length; ++i) {
            res.append(RANDOM_STRING.charAt(RANDOM.nextInt(RANDOM_STRING.length())));
        }
        return res.toString();
    }
}
