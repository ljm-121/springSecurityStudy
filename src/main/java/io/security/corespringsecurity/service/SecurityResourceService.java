package io.security.corespringsecurity.service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.security.corespringsecurity.domain.Resources;
import io.security.corespringsecurity.repository.ResourcesRepository;

public class SecurityResourceService {

	private ResourcesRepository resourcesRepository;

	public SecurityResourceService(ResourcesRepository resourcesRepository) {
		this.resourcesRepository = resourcesRepository;
	}

	public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResouceList() {
		
		LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
		List<Resources> resourcesList = resourcesRepository.findAllResources();
		resourcesList.forEach(re -> {
			List<ConfigAttribute> configAttributesList = new ArrayList<>();
			re.getRoleSet().forEach(role -> {
				configAttributesList.add(new SecurityConfig(role.getRoleName()));
			});
			result.put(new AntPathRequestMatcher(re.getResourceName()), configAttributesList);
		});
		
		return result;
	}
}
