package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.enums;

public enum MobileOSType {
    WINDOWS_PHONE(1),
    ANDROID(2),
    IOS(3),
    UNKNOWN(4);

    private final int value;

    MobileOSType(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
