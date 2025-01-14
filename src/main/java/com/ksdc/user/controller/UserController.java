package com.ksdc.user.controller;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ksdc.user.config.JwtTokenProvider;
import com.ksdc.user.dao.LoginRequest;
import com.ksdc.user.entity.User;
import com.ksdc.user.service.UserService;
import com.ksdc.user.util.UserServiceUtil;

import lombok.extern.slf4j.Slf4j;
@Slf4j
@RestController
@RequestMapping("/api/users")
public class UserController {
	
	@Autowired
	private UserService userService;

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenProvider jwtTokenProvider;
	@Autowired
	private UserServiceUtil util;

	@PostMapping("/register")
	public ResponseEntity<User> registerUser(@RequestBody User user) {
		log.debug("UserController :: registerUser start ");
	    if (user == null || user.getEmail() == null || user.getPassword() == null) {
	        return ResponseEntity.badRequest().body(null);
	    }
	    User registeredUser = userService.registrUser(user);
	    log.debug("UserController :: registerUser end "+UserServiceUtil.jsonAsString(registeredUser));
	    return ResponseEntity.status(HttpStatus.CREATED).body(registeredUser);
	}

	@GetMapping("/{id}")
	public ResponseEntity<?> getUserById(@PathVariable Integer id, Authentication authentication) {
		log.debug("UserController :: getUserById start ");
	    String loggedInUserEmail = authentication.getName(); // Get logged-in user's email
	    User user = userService.getUserById(id);
	    log.debug("UserController :: getUserById end "+UserServiceUtil.jsonAsString(user));
	    if (user != null && user.getEmail().equals(loggedInUserEmail)) {
	        return ResponseEntity.ok(user);
	    } else {
	        return ResponseEntity.status(HttpStatus.FORBIDDEN)
	                             .body("You are not authorized to access this resource.");
	    }
	}
	@GetMapping
	public ResponseEntity<?> getAllUsers() {
	    try {
	        // Fetch all users from the service layer
	        List<User> users = userService.getAllUsers();
	        
	        // Check if the list is empty
	        if (users.isEmpty()) {
	            return ResponseEntity.status(HttpStatus.NO_CONTENT)
	                                 .body("No users found.");
	        }

	        // Return the list of users in the response
	        return ResponseEntity.ok(users);
	    } catch (Exception e) {
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
	                             .body(Map.of("error", "An error occurred while fetching users.", "details", e.getMessage()));
	    }
	}



	@PostMapping("/login")
	public ResponseEntity<?> loginUser(@RequestBody LoginRequest loginRequest) {
		log.info("UserController :: loginUser start "+UserServiceUtil.jsonAsString(loginRequest));
	    try {
	        Authentication authentication = authenticationManager.authenticate(
	            new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword())
	        );

	        SecurityContextHolder.getContext().setAuthentication(authentication);
	        String jwtToken = jwtTokenProvider.generateToken((UserDetails) authentication.getPrincipal());
	        log.info("UserController :: loginUser end "+UserServiceUtil.jsonAsString(jwtToken));
	        return ResponseEntity.ok(Map.of("message", "Login successful!", "token", jwtToken));
	    } catch (BadCredentialsException e) {
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Invalid credentials!"));
	    } catch (Exception e) {
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "An error occurred during login.", "details", e.getMessage()));
	    }
	}


	@GetMapping("/generate-secret-key")
	public ResponseEntity<?> generateSecretKey() {
	    String secretKey = generateSecretKey(64);
	    return ResponseEntity.ok(Map.of("message", "Secret key generated successfully.", "secretKey", secretKey));
	}

    // Method to generate a random secret key of specified length in bytes
    private String generateSecretKey(int length) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] secretKeyBytes = new byte[length];
        secureRandom.nextBytes(secretKeyBytes);

        return Base64.getEncoder().encodeToString(secretKeyBytes);
    }
    
    @PostMapping("/validate")
    public ResponseEntity<Boolean> validateUser(@RequestBody User user) {
        User existingUser = userService.getUserById(user.getUserId());
        if (existingUser == null) {
            return ResponseEntity.ok(false);
        }

        // Validate roles if provided
        if (user.getRoles() != null && !existingUser.getRoles().containsAll(user.getRoles())) {
            return ResponseEntity.ok(false);
        }

        return ResponseEntity.ok(true);
    }

	
}
