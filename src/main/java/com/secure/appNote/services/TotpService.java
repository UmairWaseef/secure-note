package com.secure.appNote.services;

import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

public interface TotpService {
    GoogleAuthenticatorKey generateSecretKey();

    String getQrCodeUrl(GoogleAuthenticatorKey secret, String userName);

    boolean verifyCode(String secret, int code);
}
