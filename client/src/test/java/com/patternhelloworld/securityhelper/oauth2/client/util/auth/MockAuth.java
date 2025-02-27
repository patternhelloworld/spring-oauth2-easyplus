package com.patternhelloworld.securityhelper.oauth2.client.util.auth;

import io.github.patternhelloworld.securityhelper.oauth2.api.config.security.core.EasyPlusUserInfo;
import com.patternhelloworld.securityhelper.oauth2.client.domain.customer.entity.Customer;

public interface MockAuth {

    /**
     * Mock @AuthenticationPrincipal
     */
    EasyPlusUserInfo mockAuthenticationPrincipal(Customer customer);

    /**
     * Mock Customer
     */
    Customer mockCustomerObject() throws Exception;

    /**
     * Mock AccessToken
     */
    String mockAccessToken(String clientName, String clientPassword, String username, String password) throws Exception;

    /**
     * Mock AccessToken on entity (select from DB)
     */
    String mockAccessTokenOnPersistence(String authUrl, String clientName, String clientPassword, String username, String password) throws Exception;
}
