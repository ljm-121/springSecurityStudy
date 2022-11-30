package io.security.corespringsecurity.domain.dto;

import java.util.Set;

import io.security.corespringsecurity.domain.entity.Role;
import lombok.Data;

@Data
public class ResourcesDto {

	private String id;
	private String resourceName;
	private String httpMethod;
	private int orderNum;
	private String resourceType;
	private String roleName;
	private Set<Role> roleSet;
}
