package com.example;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
    public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
            security.addTokenEndpointAuthenticationFilter(new BasicAuthenticationFilter(SecurityConfig.super.authenticationManagerBean(), new AuthenticationEntryPoint() {

                @Override
                public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                    response.sendError(998);
                }
            }));
        }
    }
}
