package com.example.springsecurityjwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
    }

    //Here, when user tries to authenticate, this method is called.
    //If the credential is authenticated, then move to successfulAuthentication(...) method.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        //Grab username and password coming from request
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username is: {}", username);
        log.info("Password is: {}", password);

        //Pass the credential to UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        //Tell authenticationManager to authenticate the credential.
        return authenticationManager.authenticate(authenticationToken);
    }

    //This method takes response as an argument.
    //Using that, we can pass headers, and response body, etc.
    //In this project, we will pass a token using that response.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        User user = (User)authentication.getPrincipal(); // returns user that is successfully authenticated

        //Now, create JWT
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes()); //Algorithm to use. In real world, need to make it more complex and encrypt the secret.
        String access_token = JWT.create()
                .withSubject(user.getUsername()) // use something unique about the user as a subject
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)) //10 minutes
                .withIssuer(request.getRequestURL().toString()) // author, or company of token
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())) //add roles
                .sign(algorithm);

        String refresh_token = JWT.create()
                .withSubject(user.getUsername()) // use something unique about the user as a subject
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000)) //30 minutes
                .withIssuer(request.getRequestURL().toString()) // author, or company of token
                .sign(algorithm); // no need to pass roles

        /*
        // put tokens in header
        response.setHeader("access_token", access_token);
        response.setHeader("refresh_token", refresh_token);
        */

        //or send this in response body in JSON format
        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);
    }

}
