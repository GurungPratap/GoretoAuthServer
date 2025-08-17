package com.goreto.springauthserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;

import java.util.UUID;

@Configuration
public class AuthorizationServerClientConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        JdbcRegisteredClientRepository clientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

        // ✅ Only add if DB is empty
        if (clientRepository.findByClientId("my-client") == null) {
            RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("my-client2")
                    .clientSecret("{noop}my-secret2")
                    .clientAuthenticationMethod(org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("https://oauth.pstmn.io/v1/callback")
                    .scope("read")
                    .scope("write")
                    .clientSettings(org.springframework.security.oauth2.server.authorization.settings.ClientSettings.builder().requireAuthorizationConsent(true).build())
                    .tokenSettings(org.springframework.security.oauth2.server.authorization.settings.TokenSettings.builder().build())
                    .build();

            clientRepository.save(registeredClient);
        }

        return clientRepository;
    }
}
