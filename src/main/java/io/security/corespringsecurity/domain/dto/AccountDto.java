package io.security.corespringsecurity.domain.dto;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor

public class AccountDto {

	private Long id;
	
	private String username;
	
	private String password;
	
	private String email;
	
	private String age;
	
	private List<String> roles;
}
