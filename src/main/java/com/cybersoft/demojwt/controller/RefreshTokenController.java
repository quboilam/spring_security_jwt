package com.cybersoft.demojwt.controller;

import com.cybersoft.demojwt.jwt.JwtTokenHelper;
import com.cybersoft.demojwt.payload.response.DataResponse;
import com.cybersoft.demojwt.payload.response.TokenResponse;
import com.google.gson.Gson;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/request-token")
public class RefreshTokenController {
    @Autowired
    JwtTokenHelper jwtTokenHelper;
    private long expirationDate = 8 * 60 * 60 * 1000;
    private long refreshExpirationDate = 80 * 60 * 60 * 1000;
    private Gson gson = new Gson();

    @PostMapping("")
    public ResponseEntity<?> index(@RequestParam(name = "token") String token) {
        DataResponse dataResponse = new DataResponse();
        if(jwtTokenHelper.validateToken(token)){
            String json = jwtTokenHelper.decodeToken(token);
            Map<String, Object> subjectData = gson.fromJson(json, Map.class);
            if (StringUtils.hasText(subjectData.get("type").toString()) && subjectData.get("type").toString().equals("refresh")){
                String authToken = jwtTokenHelper.generateToken(subjectData.get("email").toString(), "auth", expirationDate);
                String refreshToken = jwtTokenHelper.generateToken(subjectData.get("email").toString(), "refresh", refreshExpirationDate);
                TokenResponse tokenResponse = new TokenResponse();
                tokenResponse.setToken(authToken);
                tokenResponse.setRefreshToken(refreshToken);

                dataResponse.setStatus(HttpStatus.OK.value());
                dataResponse.setSuccess(true);
                dataResponse.setDesc("");
                dataResponse.setData(tokenResponse);
            }
        }else {
            dataResponse.setStatus(HttpStatus.OK.value());
            dataResponse.setSuccess(true);
            dataResponse.setDesc("");
            dataResponse.setData("");
        }
        return new ResponseEntity<>(dataResponse, HttpStatus.OK);
    }
}
