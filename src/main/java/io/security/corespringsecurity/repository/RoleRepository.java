package io.security.corespringsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.security.corespringsecurity.domain.entity.Role;

public interface RoleRepository extends JpaRepository<Role, Long>{

	Role findByRoleName(String name);
	
	@Override
	void delete(Role role);
}
