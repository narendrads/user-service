package com.ksdc.user.service;

import java.util.List;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.ksdc.user.dao.Roles;

@FeignClient(name = "ROLES-SERVICE", path = "/api/roles")  // Correct path to your Roles service
public interface RolesClient {

    @GetMapping("/{id}")  // Corrected the endpoint to be consistent with the FeignClient path
    Roles getRoleById(@PathVariable("id") Long id);
    
    @PostMapping("/validate")  // No need to change this
    List<String> validateRoles(@RequestBody List<String> roleNames);
}
