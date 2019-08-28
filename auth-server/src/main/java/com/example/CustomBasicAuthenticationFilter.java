package com.example;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;



public class CustomBasicAuthenticationFilter extends BasicAuthenticationFilter {


    public CustomBasicAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
        // TODO Auto-generated constructor stub
    }

    @Override
    protected void onUnsuccessfulAuthentication(HttpServletRequest request,
    HttpServletResponse response, AuthenticationException failed) throws IOException {
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.sendError(HttpStatus.BAD_REQUEST.value(), failed.getMessage());

    }

}
