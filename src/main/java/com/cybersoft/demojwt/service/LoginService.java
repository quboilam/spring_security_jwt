package com.cybersoft.demojwt.service;

import com.cybersoft.demojwt.entity.UserEntity;

public interface LoginService {
    boolean checkLogin(String email, String password);
    UserEntity checkLogin(String email);
}
