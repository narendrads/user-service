package com.ksdc.user.dao;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Roles {
	private Long id;
	private List<String> roles;
}
