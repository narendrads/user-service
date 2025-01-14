package com.ksdc.user.service.impl;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.ksdc.user.entity.User;
import com.ksdc.user.repository.UserRepository;
import com.ksdc.user.service.RolesClient;
import com.ksdc.user.service.UserService;

import lombok.extern.slf4j.Slf4j;
@Service
@Slf4j
public class UserServiceImpl implements UserService {
    
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;	
	private final RolesClient rolesClient;
	
	public UserServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, RolesClient rolesClient) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.rolesClient = rolesClient;
	}

	@Override
	public User registrUser(User user) {
		log.info("UserServiceImpl :: registrUser start ");
		// Validate roles via RolesService
        List<String> validatedRoles = rolesClient.validateRoles(user.getRoles());

        if (validatedRoles.isEmpty()) {
            throw new IllegalArgumentException("Invalid roles provided");
        }

        // Assign validated roles to the user
        user.setRoles(validatedRoles);

        // Encode password before saving
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);
        log.info("UserServiceImpl :: registrUser end ");
		return userRepository.save(user);
	}
	
	public boolean authenticateUser(String email, String rawPassword) {
	    Optional<User> user = userRepository.findByEmail(email);
	    if (user.isPresent()) {
	        String encodedPassword = user.get().getPassword(); // Encoded password from DB
	        return passwordEncoder.matches(rawPassword, encodedPassword);
	    }
	    return false;
	}

	@Override
	public User getUserById(Integer id) { // Use Integer
	    return userRepository.findById(id).orElse(null);
	}

	@Override
	public List<User> getAllUsers() {
		return userRepository.findAll();
	}


	



}
