package io.security.corespringsecurity.security.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import io.security.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.CustomAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.CustomAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import io.security.corespringsecurity.service.SecurityResourceService;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	@Autowired
	private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
	
	@Autowired
	private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
	
	@Autowired
	private AuthenticationDetailsSource authenticationDetailsSource;

	@Autowired
	private SecurityResourceService securityResourceService;
	
	//스프링 시큐리티 기본 설정 클래스 -> 커스텀 (인증 및 validation 검사)
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}
	
	//인증 및 validation 검사 
	@Bean
	public AuthenticationProvider authenticationProvider() {
		return new CustomAuthenticationProvider();
	}

	//static 폴더는 검사x
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
	}
	
	//패스워드 인코딩 설정
	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	//인증매니저
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	@Override
	protected void configure(final HttpSecurity http) throws Exception {
		((HttpSecurity) http
			.authorizeRequests()
			.antMatchers("/","/users","user/login/**","/login*").permitAll()
			.anyRequest().authenticated()
		.and()//인가예외
			.exceptionHandling()
			.accessDeniedHandler(accessDeniedHandler())
		.and()//폼로그인설정
			.formLogin()
			.loginPage("/login")
			.loginProcessingUrl("/login_proc")
			.defaultSuccessUrl("/")
			.authenticationDetailsSource(authenticationDetailsSource)
			.successHandler(customAuthenticationSuccessHandler)
			.failureHandler(customAuthenticationFailureHandler)
			.permitAll()
		.and())
			.addFilterBefore(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class)
		;
	}

	//스프링 시큐리티 기본 설정 클래스 -> 커스텀 (인가 예외 설정)
	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
		accessDeniedHandler.setErrorPage("/denied");
		return accessDeniedHandler;
	}
	
	//스프링 시큐리티 기본 설정 클래스 -> 커스텀 // 인가 예외 설정
	public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {
		
		FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
		filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
		filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
		filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
		
		return filterSecurityInterceptor;
	}

	@Bean
	public AccessDecisionManager affirmativeBased() {
		AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecistionVoters());
		return affirmativeBased;
	}

	private List<AccessDecisionVoter<?>> getAccessDecistionVoters() {
		return Arrays.asList(new RoleVoter());
	}

	//DB로부터 자원 권한 정보 저장
	@Bean
	public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {
		return new UrlFilterInvocationSecurityMetadataSource(urlResourcesMapFactoryBean().getObject());
	}
	
	private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
		
		UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
		urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
		
		return urlResourcesMapFactoryBean;
	}
	
}
