package com.cybersoft.demojwt.service;

import com.cybersoft.demojwt.entity.UserEntity;
import com.cybersoft.demojwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class LoginServiceImp implements LoginService{
    @Autowired
    UserRepository userRepository;

    @Override
    public boolean checkLogin(String email, String password) {
        List<UserEntity> users = userRepository.findByEmailAndPassword(email, password);

        return users.size() > 0;
    }

    @Override
    public UserEntity checkLogin(String email) {
        List<UserEntity> users = userRepository.findByEmail(email);
        return users.size() > 0 ? users.get(0) : null;
    }
}
