package com.example;

import org.springframework.boot.autoconfigure.security.oauth2.authserver.OAuth2AuthorizationServerConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.ClientDetailsUserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

@Configuration
@Order(-20)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.debug(true);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
		http
			.requestMatchers().antMatchers("/", "/login**", "/webjars/**","/error**")
            .and()
            .authorizeRequests().antMatchers("/", "/login**", "/webjars/**","/error**").permitAll().anyRequest()
				.authenticated();
		// @formatter:on
    }


    @Configuration
    @EnableAuthorizationServer
    @Import(OAuth2AuthorizationServerConfiguration.class)
    public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

        private final ClientDetailsService clientDetailsService;

        public AuthorizationServerConfig(ClientDetailsService clientDetailsService) {
            this.clientDetailsService = clientDetailsService;
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
            final PasswordEncoder passwordEncoder = NoOpPasswordEncoder.getInstance();
            final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
            authenticationProvider.setUserDetailsService(new ClientDetailsUserDetailsService(this.clientDetailsService));
            authenticationProvider.setPasswordEncoder(new PasswordEncoder() {

                @Override
                public boolean matches(CharSequence rawPassword, String encodedPassword) {
                    return !StringUtils.hasText(encodedPassword) || passwordEncoder.matches(rawPassword, encodedPassword);
                }

                @Override
                public String encode(CharSequence rawPassword) {
                    return passwordEncoder.encode(rawPassword);
                }
            });

            final ProviderManager authenticationManager = new ProviderManager(Collections.singletonList(authenticationProvider));
            authenticationManager.afterPropertiesSet();

            final AuthenticationEntryPoint authenticationEntryPoint = new AuthenticationEntryPoint() {

                @Override
                public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                    response.sendError(400, "Custom Error!");
                }
            };
            security.addTokenEndpointAuthenticationFilter(new BasicAuthenticationFilter(authenticationManager, authenticationEntryPoint));
        }
    }
}
