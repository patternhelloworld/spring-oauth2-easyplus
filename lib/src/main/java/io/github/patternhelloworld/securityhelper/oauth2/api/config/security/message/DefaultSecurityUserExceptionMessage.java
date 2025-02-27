package io.github.patternhelloworld.securityhelper.oauth2.api.config.security.message;


public enum DefaultSecurityUserExceptionMessage implements ExceptionMessageInterface {

    AUTHENTICATION_LOGIN_FAILURE("Authentication information is not valid. Please check and try again."),
    AUTHENTICATION_LOGIN_ERROR("An error occurred during authentication. If the problem persists, please contact customer service."),
    AUTHENTICATION_TOKEN_FAILURE("The authentication token has expired. Please log in again."),
    AUTHENTICATION_TOKEN_ERROR("There was a problem verifying the authentication token. Please log in again."),
    AUTHORIZATION_FAILURE("You do not have access permissions. Please request this from the administrator."),
    AUTHORIZATION_ERROR("An error occurred with access permissions. If the problem persists, please contact customer service."),

    // ID PASSWORD
    AUTHENTICATION_ID_NO_EXISTS("The specified ID does not exist."),
    AUTHENTICATION_WRONG_ID_PASSWORD("User information could not be verified. Please check your ID or password. If the problem persists, please contact customer service."),
    AUTHENTICATION_PASSWORD_FAILED_EXCEEDED("The number of password attempts has been exceeded."),

    // Wrong Authorization Code
    AUTHENTICATION_INVALID_RESPONSE_TYPE("The specified Response Type is invalid."),
    AUTHENTICATION_INVALID_AUTHORIZATION_CODE("The specified Authorization Code is invalid."),
    AUTHENTICATION_EXPIRED_AUTHORIZATION_CODE("The specified Authorization Code has been expired."),
    AUTHENTICATION_INVALID_REDIRECT_URI("The specified Redirect URI is invalid."),
    AUTHENTICATION_SCOPES_NOT_APPROVED("The specified Scopes are not approved."),
    // CLIENT ID, SECRET
    AUTHENTICATION_WRONG_CLIENT_ID_SECRET("Client information is not verified."),

    // GRANT TYPE
    AUTHENTICATION_WRONG_GRANT_TYPE("Wrong Grant Type detected."),
    AUTHENTICATION_WRONG_COMBINATION_OF_GRANT_TYPE_RESPONSE_TYPE("Grant Type doesn't match response type."),

    // OAuth2 : Authorization Code
    AUTHENTICATION_AUTHORIZATION_CODE_REQUEST_WRONG_METHOD("Wrong Authorization Code request."),
    AUTHENTICATION_CLIENT_ID_MISSING("Client ID is missing."),
    AUTHENTICATION_REDIRECT_URI_MISSING("Redirect URI is missing."),
    AUTHENTICATION_STATE_MISSING("State is missing."),
    AUTHENTICATION_REGISTERED_CLIENT_NOT_FOUND("Registered client is missing or invalid"),
    AUTHENTICATION_AUTHORIZATION_CODE_MISSING("Authorization Code is missing.");

    private String message;

    @Override
    public String getMessage() {
        return message;
    }

    DefaultSecurityUserExceptionMessage(String message) {
        this.message = message;
    }

}
