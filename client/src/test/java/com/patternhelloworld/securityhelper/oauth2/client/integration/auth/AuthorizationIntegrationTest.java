package com.patternhelloworld.securityhelper.oauth2.client.integration.auth;


import jakarta.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.restdocs.RestDocumentationContextProvider;
import org.springframework.restdocs.RestDocumentationExtension;
import org.springframework.restdocs.mockmvc.RestDocumentationResultHandler;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.WebApplicationContext;

import java.io.UnsupportedEncodingException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


/*
*    Functions ending with
*       "ORIGINAL" : '/oauth2/token'
*       "EXPOSED" : '/api/v1/traditional-oauth/token'
* */
@ExtendWith(RestDocumentationExtension.class)
@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@AutoConfigureRestDocs(outputDir = "target/generated-snippets",uriScheme = "http", uriHost = "localhost", uriPort = 8370)
public class AuthorizationIntegrationTest {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationIntegrationTest.class);


    @Autowired
    private MockMvc mockMvc;


    @Value("${app.oauth2.appUser.clientId}")
    private String appUserClientId;
    @Value("${app.oauth2.appUser.clientSecret}")
    private String appUserClientSecret;

    @Value("${app.test.auth.customer.username}")
    private String testUserName;
    @Value("${app.test.auth.customer.password}")
    private String testUserPassword;


    private RestDocumentationResultHandler document;

    private String basicHeader;

    @Autowired
    private WebApplicationContext webApplicationContext;


    @BeforeEach
    public void setUp(RestDocumentationContextProvider restDocumentationContextProvider) throws UnsupportedEncodingException {

        basicHeader = "Basic " + DatatypeConverter.printBase64Binary((appUserClientId + ":" + appUserClientSecret).getBytes("UTF-8"));

    }

    @Test
    public void testAuthorizationCodeMissingException() throws Exception {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(OAuth2ParameterNames.RESPONSE_TYPE, "code");
        parameters.set(OAuth2ParameterNames.CLIENT_ID, "client_customer");
        parameters.set(OAuth2ParameterNames.REDIRECT_URI, "http://localhost:8081/callback1");
        parameters.set(OAuth2ParameterNames.SCOPE, "read");
        parameters.set(OAuth2ParameterNames.STATE, "xxx");

        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .queryParams(parameters))
                        .andExpect(status().is2xxSuccessful())
                        .andDo(print())
                        .andReturn();

        assertEquals("/login", result.getResponse().getForwardedUrl(),
                "The request should be forwarded to the login page due to missing authorization code.");
    }


}