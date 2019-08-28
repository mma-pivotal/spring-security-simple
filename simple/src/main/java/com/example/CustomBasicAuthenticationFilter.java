package com.example;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;



public class CustomBasicAuthenticationFilter extends BasicAuthenticationFilter {


    public CustomBasicAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
          throws IOException, ServletException {
              System.out.println("================================================");
      super.doFilterInternal(request, response, chain);
  }

    @Override
    protected void onUnsuccessfulAuthentication(HttpServletRequest request,
    HttpServletResponse response, AuthenticationException failed) throws IOException {
        response.setStatus(HttpStatus.BAD_REQUEST.value());
        response.sendError(HttpStatus.BAD_REQUEST.value(), failed.getMessage());

    }

}
