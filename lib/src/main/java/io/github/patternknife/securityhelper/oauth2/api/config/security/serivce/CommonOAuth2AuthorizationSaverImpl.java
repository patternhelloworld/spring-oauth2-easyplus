package io.github.patternknife.securityhelper.oauth2.api.config.security.serivce;

import io.github.patternknife.securityhelper.oauth2.api.config.logger.KnifeSecurityLogConfig;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.DefaultSecurityUserExceptionMessage;
import io.github.patternknife.securityhelper.oauth2.api.config.security.message.ISecurityUserExceptionMessageService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.dto.KnifeErrorMessages;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.util.KnifeHttpHeaders;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.authentication.OAuth2AuthorizationBuildingService;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;

import io.github.patternknife.securityhelper.oauth2.api.config.util.SecurityExceptionUtils;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;

import java.util.Map;

/*
*    Saver : Persist
*         Implements the logic for persisting OAuth2Authorization based on the provided grant type.
*         Supports various grant types and handles duplicate exceptions gracefully.
* */
@Service
@RequiredArgsConstructor
public class CommonOAuth2AuthorizationSaverImpl implements CommonOAuth2AuthorizationSaver {

     private static final Logger logger = LoggerFactory.getLogger(KnifeSecurityLogConfig.class);

     private final OAuth2AuthorizationBuildingService oAuth2AuthorizationBuildingService;
     private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;
     private final ISecurityUserExceptionMessageService iSecurityUserExceptionMessageService;

     /**
      * Handles OAuth2Authorization persistence based on the grant type.
      *
      * <p><b>Grant Types:</b></p>
      * <ul>
      *     <li><b>AUTHORIZATION_CODE</b>: Generates a "code" using "username" and "password".</li>
      *     <li><b>CODE</b>: Generates an "access_token" using the "code".</li>
      *     <li><b>PASSWORD</b>: Generates an "access_token" using "username" and "password".</li>
      *     <li><b>REFRESH_TOKEN</b>: Generates a "refresh_token" using the "access_token".</li>
      * </ul>
      *
      * <p><b>retryOnDuplicateException:</b></p>
      * <p>
      * While the Spring Authorization Server is generally not expected to cause duplicate exceptions,
      * such errors have been observed in the past. This method includes preventive measures to handle
      * potential issues gracefully by retrying the operation.
      * </p>
      *
      * @param userDetails the details of the authenticated user.
      * @param authorizationGrantType the type of authorization grant.
      * @param clientId the client ID.
      * @param additionalParameters additional parameters for the OAuth2 flow.
      * @param modifiableAdditionalParameters additional parameters that may be modified during the flow.
      * @return the persisted {@link OAuth2Authorization} object.
      * @throws KnifeOauth2AuthenticationException if an authentication error occurs.
      */
     @Override
     public @NotNull OAuth2Authorization save(UserDetails userDetails, AuthorizationGrantType authorizationGrantType, String clientId,
                                              Map<String, Object> additionalParameters, Map<String, Object> modifiableAdditionalParameters) {

          if (authorizationGrantType.getValue().equals(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())) {
               return SecurityExceptionUtils.retryOnDuplicateException(() -> {
                    // In-memory build
                    OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationBuildingService.build(
                            userDetails, authorizationGrantType, clientId, additionalParameters, null);
                    // Persist
                    oAuth2AuthorizationService.save(oAuth2Authorization);
                    return oAuth2Authorization;
               }, 5, logger, "[Authorization Code] An error occurred with the Key during the execution of persistOAuth2Authorization for " + userDetails.getUsername());

          }else {

               OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByUserNameAndClientIdAndAppToken(
                       userDetails.getUsername(), clientId, (String) additionalParameters.get(KnifeHttpHeaders.APP_TOKEN));

               if (authorizationGrantType.getValue().equals(AuthorizationGrantType.PASSWORD.getValue())
                    || authorizationGrantType.getValue().equals(OAuth2ParameterNames.CODE)) {

                    if(authorizationGrantType.getValue().equals(OAuth2ParameterNames.CODE)){
                         OAuth2Authorization oAuth2AuthorizationForCodeVerification = oAuth2AuthorizationService.findByAuthorizationCode(additionalParameters.get(OAuth2ParameterNames.CODE).toString());
                         if(oAuth2AuthorizationForCodeVerification == null) {
                              throw new KnifeOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_INVALID_AUTHORIZATION_CODE));
                         }else{
                              OAuth2Authorization.Token<OAuth2AuthorizationCode> oAuth2Token =oAuth2AuthorizationForCodeVerification.getToken(OAuth2AuthorizationCode.class);
                              if(oAuth2Token == null){
                                   throw new KnifeOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_INVALID_AUTHORIZATION_CODE));
                              }
                              if(oAuth2Token.isExpired()){
                                   throw new KnifeOauth2AuthenticationException(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_EXPIRED_AUTHORIZATION_CODE));
                              }
                         }
                    }

                    if (oAuth2Authorization == null || oAuth2Authorization.getAccessToken().isExpired()) {
                         return SecurityExceptionUtils.retryOnDuplicateException(() -> {
                              // In-memory build
                              OAuth2Authorization authorization = oAuth2AuthorizationBuildingService.build(
                                      userDetails, authorizationGrantType, clientId, additionalParameters, null);
                              // Persist
                              oAuth2AuthorizationService.save(authorization);
                              return authorization;
                         }, 5, logger, "[Access Token] An error occurred with the Key during the execution of persistOAuth2Authorization for " + userDetails.getUsername());
                    }
               } else if (authorizationGrantType.getValue().equals(AuthorizationGrantType.REFRESH_TOKEN.getValue())) {
                    return SecurityExceptionUtils.retryOnDuplicateException(() -> {
                         String refreshTokenValue = (String) (additionalParameters.containsKey("refresh_token") ? additionalParameters.get("refresh_token")
                                 : modifiableAdditionalParameters.get("refresh_token"));

                         OAuth2Authorization oAuth2AuthorizationFromRefreshToken = oAuth2AuthorizationService.findByToken(refreshTokenValue, OAuth2TokenType.REFRESH_TOKEN);

                         if (oAuth2AuthorizationFromRefreshToken == null || oAuth2AuthorizationFromRefreshToken.getRefreshToken().isExpired()) {
                              oAuth2AuthorizationService.remove(oAuth2AuthorizationFromRefreshToken);
                              throw new KnifeOauth2AuthenticationException("Refresh Token Expired.");
                         }

                         OAuth2RefreshToken shouldBePreservedRefreshToken = oAuth2AuthorizationFromRefreshToken.getRefreshToken().getToken();
                         oAuth2AuthorizationService.remove(oAuth2AuthorizationFromRefreshToken);

                         // In-memory build
                         OAuth2Authorization authorization = oAuth2AuthorizationBuildingService.build(
                                 userDetails, authorizationGrantType, clientId, additionalParameters, shouldBePreservedRefreshToken);
                         // Persist
                         oAuth2AuthorizationService.save(authorization);
                         return authorization;

                    }, 5, logger, "[Refresh Token] An error occurred with the Key during the execution of persistOAuth2Authorization for " + userDetails.getUsername());
               } else {
                    throw new KnifeOauth2AuthenticationException(KnifeErrorMessages.builder().message("Wrong grant type from Req : " + authorizationGrantType.getValue()).userMessage(iSecurityUserExceptionMessageService.getUserMessage(DefaultSecurityUserExceptionMessage.AUTHENTICATION_WRONG_GRANT_TYPE)).build());
               }

               return oAuth2Authorization;
          }
     }
}

