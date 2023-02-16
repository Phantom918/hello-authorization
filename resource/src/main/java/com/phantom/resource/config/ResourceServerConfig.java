package com.phantom.resource.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.SecurityFilterChain;

import java.nio.charset.StandardCharsets;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@Slf4j
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/messages/**")
                .authorizeHttpRequests()
                .requestMatchers("/messages/**").hasAuthority("SCOPE_message.read")
//					.requestMatchers("/messages/**").authenticated()
                .and()
                // 不创建 session
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .oauth2ResourceServer()
                .jwt()
                .and()
                // 认证失败
                .authenticationEntryPoint((request, response, exception) -> {
                    // oauth2 认证失败导致的，还有一种可能是非oauth2认证失败导致的，比如没有传递token，但是访问受权限保护的方法
                    if (exception instanceof OAuth2AuthenticationException) {
                        OAuth2AuthenticationException oAuth2AuthenticationException = (OAuth2AuthenticationException) exception;
                        OAuth2Error error = oAuth2AuthenticationException.getError();
                        log.info("认证失败,异常类型:[{}],异常:[{}]", exception.getClass().getName(), error);
                    }
                    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                    response.setContentType(MediaType.APPLICATION_JSON.toString());
                    response.getWriter().write("{\"code\":-3,\"message\":\"您无权限访问\"}");
                })
                // 认证成功后，无权限访问
                .accessDeniedHandler((request, response, exception) -> {

                    log.info("您无权限访问,异常类型:[{}]", exception.getClass().getName());
                    log.info("异常信息:[{}]", exception.getMessage());
                    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
                    response.setContentType(MediaType.APPLICATION_JSON.toString());
                    response.getWriter().write("{\"code\":-4,\"message\":\"您无权限访问\"}");
                })
        ;
        return http.build();
    }

}
