package com.cybersoft.demojwt.controller;

import com.cybersoft.demojwt.jwt.JwtTokenHelper;
import com.cybersoft.demojwt.payload.request.SignInRequest;
import com.cybersoft.demojwt.payload.response.DataResponse;
import com.cybersoft.demojwt.payload.response.TokenResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/signin")
public class LoginController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtTokenHelper jwtTokenHelper;

    private long expirationDate = 8 * 60 * 60 * 1000;
    private long refreshExpirationDate = 80 * 60 * 60 * 1000;

    @PostMapping ("")
    public ResponseEntity<?> signin(@RequestBody SignInRequest signInRequest) {
        UsernamePasswordAuthenticationToken authReq
                = new UsernamePasswordAuthenticationToken(signInRequest.getEmail(), signInRequest.getPassword());

        Authentication auth = authenticationManager.authenticate(authReq);
        SecurityContextHolder.getContext().setAuthentication(auth);



        String token = jwtTokenHelper.generateToken(signInRequest.getEmail(), "auth", expirationDate);
        String refreshToken = jwtTokenHelper.generateToken(signInRequest.getEmail(), "refresh", refreshExpirationDate);

        TokenResponse tokenResponse = new TokenResponse();
        tokenResponse.setToken(token);
        tokenResponse.setRefreshToken(refreshToken);

        DataResponse dataResponse = new DataResponse();
        dataResponse.setStatus(200);
        dataResponse.setSuccess(true);
        dataResponse.setDesc("");
        dataResponse.setData(tokenResponse);

        return new ResponseEntity<>(dataResponse, HttpStatus.OK);
    }

    @GetMapping("/test")
    public String test() {
        return "Test";
    }
}
