package com.ksdc.user.service;

import java.util.List;

import com.ksdc.user.entity.User;

public interface UserService {
public User registrUser(User user);

public boolean authenticateUser(String email, String password);
public User getUserById(Integer id);
public List<User> getAllUsers();
}
