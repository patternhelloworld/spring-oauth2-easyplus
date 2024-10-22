package io.github.patternknife.securityhelper.oauth2.api.config.security.converter.auth.endpoint;


import io.github.patternknife.securityhelper.oauth2.api.config.security.dao.KnifeAuthorizationConsentRepository;
import io.github.patternknife.securityhelper.oauth2.api.config.security.response.error.exception.KnifeOauth2AuthenticationException;
import io.github.patternknife.securityhelper.oauth2.api.config.security.serivce.persistence.authorization.OAuth2AuthorizationServiceImpl;
import io.github.patternknife.securityhelper.oauth2.api.config.util.RequestOAuth2Distiller;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;


import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;

@RequiredArgsConstructor
public final class AuthorizationCodeRequestAuthenticationConverter implements AuthenticationConverter {

    /*
     *   `
     *      CustomGrantAuthenticationToken <- OAuth2ClientAuthenticationToken
     *
     * */
    private final RegisteredClientRepository registeredClientRepository;
    private final KnifeAuthorizationConsentRepository knifeAuthorizationConsentRepository;
    private final OAuth2AuthorizationServiceImpl oAuth2AuthorizationService;

    public void setClientAuthentication(String clientId) {

        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);

        if (registeredClient == null) {
            throw new IllegalArgumentException("Invalid client ID");
        }

        OAuth2ClientAuthenticationToken clientAuthenticationToken = new OAuth2ClientAuthenticationToken(registeredClient , ClientAuthenticationMethod.CLIENT_SECRET_BASIC, null);

        SecurityContextHolder.getContext().setAuthentication(clientAuthenticationToken);
    }

    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        MultiValueMap<String, String> parameters = RequestOAuth2Distiller.getAuthorizationCodeSecurityAdditionalParameters(request);

        String authorizationCode = parameters.getFirst(OAuth2ParameterNames.CODE);
        if (authorizationCode == null) {
            throw new KnifeOauth2AuthenticationException("non -code");
        }


        OAuth2Authorization oAuth2Authorization = oAuth2AuthorizationService.findByToken(authorizationCode, new OAuth2TokenType("authorization_code"));
        if(oAuth2Authorization == null){
            throw new KnifeOauth2AuthenticationException("non -code");
        }
        String principalName = oAuth2Authorization.getPrincipalName();

        // 클라이언트 인증 설정
        setClientAuthentication(parameters.getFirst(OAuth2ParameterNames.CLIENT_ID));
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        // code (REQUIRED) - Authorization Code 요청 시에는 아직 발급되지 않음
        String code = parameters.getFirst(OAuth2ParameterNames.CODE);
        if (!StringUtils.hasText(code) || parameters.get(OAuth2ParameterNames.CODE).size() != 1) {
            // 예외 처리 필요 시 여기에 추가
        }

        // redirect_uri (REQUIRED)
        String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
        if (StringUtils.hasText(redirectUri) && parameters.get(OAuth2ParameterNames.REDIRECT_URI).size() != 1) {
            // 예외 처리 필요 시 여기에 추가
        }

        // scopes
        Set<String> scopes = new HashSet<>(parameters.getOrDefault(OAuth2ParameterNames.SCOPE, Collections.emptyList()));

        // 추가적인 파라미터 처리
        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            additionalParameters.put(key, (value.size() == 1) ? value.get(0) : value.toArray(new String[0]));
        });

        //      if(knifeAuthorizationConsentRepository.findByRegisteredClientIdAndPrincipalName())
        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .clientId(parameters.getFirst(OAuth2ParameterNames.CLIENT_ID))
                .authorizationUri(parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI))
                .redirectUri(parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI))
                .scopes(scopes) // 스코프 설정
                .state(parameters.getFirst(OAuth2ParameterNames.STATE))
                .build();
        additionalParameters.put(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);
        // grant_type (REQUIRED)

        return new OAuth2AuthorizationCodeAuthenticationToken(
                code,
                clientPrincipal, // principal (사용자 인증 객체)
                redirectUri, // redirectUri
                additionalParameters // 추가 파라미터
        );
        // OAuth2AuthorizationCodeRequestAuthenticationToken 생성
    }


}
