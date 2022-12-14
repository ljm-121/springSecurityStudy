package io.security.corespringsecurity.security.listener;

import org.springframework.transaction.annotation.Transactional;

import io.security.corespringsecurity.domain.entity.AccessIp;
import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.domain.entity.Role;
import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.repository.RoleHierarchyRepository;
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
	private RoleHierarchyRepository roleHierarchyRepository;
	
	@Autowired
    private PasswordEncoder passwordEncoder;
	
    @Autowired
    private AccessIpRepository accessIpRepository;
	
	@Override
	@Transactional
	public void onApplicationEvent(ContextRefreshedEvent event) {
		
		if(alreadySetup) {
			return;
		}
		
		setupSecurityResources();
		
		setupAccessIpData();
		
		alreadySetup = true;
	}

	private void setupAccessIpData() {
		AccessIp byIpAddress = accessIpRepository.findByIpAddress("0:0:0:0:0:0:0:1");
        if (byIpAddress == null) {
            AccessIp accessIp = AccessIp.builder()
                    .ipAddress("192.168.0.19")
            		.build();
            accessIpRepository.save(accessIp);
        }
	}

	private void setupSecurityResources() {
		Set<Role> roles = new HashSet<>();
		Role adminRole = createRoleIfNotFound("ROLE_ADMIN","?????????");
		roles.add(adminRole);
		createUserIfNotFound("admin","admin@admin.com","1234",roles);
		Role managerRole = createRoleIfNotFound("ROLE_MANAGER", "???????????????");
        Role userRole = createRoleIfNotFound("ROLE_USER", "???????????????");
        createRoleHierarchyIfNotFound(managerRole, adminRole);
        createRoleHierarchyIfNotFound(userRole, managerRole);
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

	@Transactional
	private void createRoleHierarchyIfNotFound(Role childRole, Role parentRole) {
		
		RoleHierarchy roleHierarchy = roleHierarchyRepository.findByChildName(parentRole.getRoleName());
		if(roleHierarchy == null) {
			roleHierarchy = RoleHierarchy.builder()
					.childName(parentRole.getRoleName())
					.build();
		}
		RoleHierarchy parentRoleHierarchy = roleHierarchyRepository.save(roleHierarchy);
		roleHierarchy = roleHierarchyRepository.findByChildName(childRole.getRoleName());
        if (roleHierarchy == null) {
            roleHierarchy = RoleHierarchy.builder()
                    .childName(childRole.getRoleName())
                    .build();
        }
        RoleHierarchy childRoleHierarchy = roleHierarchyRepository.save(roleHierarchy);
        childRoleHierarchy.setParentName(parentRoleHierarchy);
	}
}
