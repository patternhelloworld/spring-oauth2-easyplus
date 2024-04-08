package com.patternknife.securityhelper.oauth2.config.response.error.exception.auth;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

// UNAUTHORIZED : 401
// FORBIDDEN : 403
@ResponseStatus(value = HttpStatus.UNAUTHORIZED)
public class NoSocialRegisteredException extends RuntimeException {
    public NoSocialRegisteredException(String message) {
        super(message);
    }
}