package com.phantom.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.phantom.server.jose.Jwks;
import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;

/**
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 */
@Slf4j
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    /**
     * ?????????????????????????????? url
     */
    private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

    @Resource
    private PasswordEncoder passwordEncoder;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();


        authorizationServerConfigurer
                // ????????????
                .authorizationEndpoint(configurer -> {
                    // ??????????????????
                    configurer.consentPage(CUSTOM_CONSENT_PAGE_URI);
                    // ????????????????????????????????????????????????
                    configurer.errorResponseHandler((request, response, exception) -> {
                        OAuth2AuthenticationException authenticationException = (OAuth2AuthenticationException) exception;
                        OAuth2Error error = authenticationException.getError();
                        log.error("????????????:[{}]", error);
                        log.info("????????????", exception);
                        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                        response.setContentType(MediaType.APPLICATION_JSON.toString());
                        response.getWriter().write("{\"code\":-1,\"msg\":\"??????????????????\"}");
                    });
                })
                // token ??????
                .tokenEndpoint(configurer -> {
                    configurer.errorResponseHandler((request, response, exception) -> {
                        OAuth2AuthenticationException oAuth2AuthenticationException = (OAuth2AuthenticationException) exception;
                        OAuth2Error error = oAuth2AuthenticationException.getError();
                        log.error("????????????:[{}]", error);
                        log.info("????????????", exception);
                        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                        response.setContentType(MediaType.APPLICATION_JSON.toString());
                        response.getWriter().write("{\"code\":-1,\"msg\":\"toekn????????????\"}");
                    });
                })
                // Enable OpenID Connect 1.0
                .oidc(Customizer.withDefaults())
                .addObjectPostProcessor(new ObjectPostProcessor<Object>() {
                    @Override
                    public <O> O postProcess(O object) {
                        if (object instanceof OAuth2ClientAuthenticationFilter) {
                            OAuth2ClientAuthenticationFilter filter = (OAuth2ClientAuthenticationFilter) object;
                            filter.setAuthenticationFailureHandler((request, response, exception) -> {
                                OAuth2AuthenticationException oAuth2AuthenticationException = (OAuth2AuthenticationException) exception;
                                OAuth2Error oAuth2Error = oAuth2AuthenticationException.getError();
                                switch (oAuth2Error.getErrorCode()) {
                                    case OAuth2ErrorCodes.INVALID_CLIENT:
                                        log.info("??????????????????");
                                        break;
                                    case OAuth2ErrorCodes.ACCESS_DENIED:
                                        log.info("??????????????????");
                                        break;
                                    default:
                                        break;
                                }
                                log.error("????????????:[{}]", oAuth2Error);
                                log.info("????????????", exception);
                                response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                                response.setContentType(MediaType.APPLICATION_JSON.toString());
                                response.getWriter().write("{\"code\":-2,\"msg\":\"????????????!\"}");
                            });
                        }
                        return object;
                    }
                });
        ;

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        http
                .securityMatcher(endpointsMatcher)
                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest().authenticated()
                )
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .exceptionHandling(exceptions ->
                        exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .apply(authorizationServerConfigurer);

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                // ???????????? secret, ?????????{noop}??????????????????????????????????????????spring?????? noop ?????????????????????
                //.clientSecret("{noop}secret")
                .clientSecret(passwordEncoder.encode("secret"))
                // ???????????? CLIENT_SECRET_POST ???????????????????????????????????????
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // ??????????????? ???????????????????????????????????????????????????, ????????????????????????????????????????????????"???????????????"??????????????????????????????
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // ??????token
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // ??????????????? ??????????????????????????????????????????????????????????????????"???????????????"???????????????
                // ??????????????????????????????????????????OAuth??????????????????????????????
                // ???????????????????????????????????????????????????????????????????????????????????????"???????????????"?????????????????????????????????????????????
                //.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-authorization-code")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        RegisteredClient client1 = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client1")
                //.clientSecret("{noop}123456")
                .clientSecret(passwordEncoder.encode("123456"))
                // ??????????????????
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                // ?????????
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // ??????token
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8081/callback")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder()
                        // ????????????????????????????????????????????????
                        .requireAuthorizationConsent(true)
                        .build()
                )
                .tokenSettings(TokenSettings.builder()
                        // accessToken ????????????
                        .accessTokenTimeToLive(Duration.ofMinutes(60))
                        // refreshToken ????????????
                        .refreshTokenTimeToLive(Duration.ofHours(2))
                        // ???????????????????????????
                        .reuseRefreshTokens(true)
                        .build()
                )
                .build();

        // ?????????????????????????????????
        JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        if (null == registeredClientRepository.findByClientId("messaging-client")) {
            registeredClientRepository.save(client);
        }
        if (null == registeredClientRepository.findByClientId("client1")) {
            registeredClientRepository.save(client1);
        }

        return registeredClientRepository;
//        return new InMemoryRegisteredClientRepository(client, client1);

    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                // ??????????????????????????????url
                .authorizationEndpoint("/my/authorize")
                // ????????????url??????, ?????????????????????????????????
                .issuer("http://127.0.0.1:9000")
                .build();
    }

    /**
     * ????????????????????????????????????????????????
     *
     * @return
     */
//    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }

    /**
     * ???????????????????????????????????????????????????
     *
     * @return
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * ???????????????????????????????????????????????????
     * "org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql"
     *
     * @return
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * ?????????????????????
     *
     * @return
     */
    public EmbeddedDatabase embeddedDatabase() {
        return new EmbeddedDatabaseBuilder()
                .generateUniqueName(true)
                .setType(EmbeddedDatabaseType.H2)
                .setScriptEncoding("UTF-8")
                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
                .addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
                .addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
                .build();
    }



}
