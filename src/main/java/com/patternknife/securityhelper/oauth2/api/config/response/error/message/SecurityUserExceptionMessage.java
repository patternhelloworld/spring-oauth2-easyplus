package com.patternknife.securityhelper.oauth2.api.config.response.error.message;


public enum SecurityUserExceptionMessage implements ExceptionMessageInterface {

    AUTHENTICATION_LOGIN_FAILURE("Authentication information is not valid. Please check and try again."),
    AUTHENTICATION_LOGIN_ERROR("An error occurred during authentication. If the problem persists, please contact customer service."),
    AUTHENTICATION_TOKEN_FAILURE("The authentication token has expired. Please log in again."),
    AUTHENTICATION_TOKEN_ERROR("There was a problem verifying the authentication token. Please log in again."),
    AUTHORIZATION_FAILURE("You do not have access permissions. Please request this from the administrator."),
    AUTHORIZATION_ERROR("An error occurred with access permissions. If the problem persists, please contact customer service."),

    // ID PASSWORD
    ID_NO_EXISTS("The specified ID does not exist."),
    WRONG_ID_PASSWORD("User information could not be verified. Please check your ID or password. If the problem persists, please contact customer service."),
    PASSWORD_FAILED_EXCEEDED("The number of password attempts has been exceeded."),

    // CLIENT ID, SECRET
    WRONG_CLIENT_ID_SECRET("Client information is not verified."),

    // GRANT TYPE
    WRONG_GRANT_TYPE("Wrong Grant Type");

    private String message;

    @Override
    public String getMessage() {
        return message;
    }

    SecurityUserExceptionMessage(String message) {
        this.message = message;
    }

}
