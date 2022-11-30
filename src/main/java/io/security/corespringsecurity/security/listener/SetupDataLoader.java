package io.security.corespringsecurity.security.listener;

import org.springframework.transaction.annotation.Transactional;

import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.repository.RoleRepository;
import io.security.corespringsecurity.repository.UserRepository;

import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent>{

	private boolean alreadySetup = false;
	
	@Autowired
	private RoleRepository roleRepository;
	
	@Autowired
    private UserRepository userRepository;
	
	@Autowired
    private PasswordEncoder passwordEncoder;
	
	@Override
	@Transactional
	public void onApplicationEvent(ContextRefreshedEvent event) {
		
		if(alreadySetup) {
			return;
		}
		
		setupSecurityResources();
		
		alreadySetup = true;
	}

	private void setupSecurityResources() {
		Set<Role> roles = new HashSet<>();
		Role adminRole = createRoleIfNotFound("ROLE_ADMIN","관리자");
		roles.add(adminRole);
		createUserIfNotFound("admin","admin@admin.com","1234",roles);
		Role managerRole = createRoleIfNotFound("ROLE_MANAGER", "매니저권한");
        Role userRole = createRoleIfNotFound("ROLE_USER", "사용자권한");
	}

	@Transactional
	private Account createUserIfNotFound(final String userName, final String email, final String password, Set<Role> roleSet) {
		 Account account = userRepository.findByUsername(userName);

        if (account == null) {
            account = Account.builder()
                    .username(userName)
                    .email(email)
                    .password(passwordEncoder.encode(password))
                    .userRoles(roleSet)
                    .build();
        }
        return userRepository.save(account);
	}

	@Transactional
	private Role createRoleIfNotFound(String roleName, String roleDesc) {
		
		Role role = roleRepository.findByRoleName(roleName);
		
		if(role == null) {
			role = Role.builder()
					.roleName(roleName)
					.roleDesc(roleDesc)
					.build();
		}
		return roleRepository.save(role);
	}

}
