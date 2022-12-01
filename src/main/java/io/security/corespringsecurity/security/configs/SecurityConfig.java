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
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import io.security.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.security.corespringsecurity.security.filter.PermitAllFilter;
import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.CustomAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.CustomAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.security.corespringsecurity.security.provider.FormAuthenticationProvider;
import io.security.corespringsecurity.service.SecurityResourceService;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{

    @Autowired
    private AuthenticationSuccessHandler formAuthenticationSuccessHandler;
    @Autowired
    private AuthenticationFailureHandler formAuthenticationFailureHandler;
    
	@Autowired
	private CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
	
	@Autowired
	private CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
	
	@Autowired
	private AuthenticationDetailsSource authenticationDetailsSource;

	@Autowired
	private SecurityResourceService securityResourceService;
	
	private String[] permitAllResources = {"/", "/login", "/user/login/**"};

	//static 폴더는 검사x
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
	}
	
	//스프링 시큐리티 기본 설정 클래스 -> 커스텀 (인증 및 validation 검사)
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(authenticationProvider());
	}
	
	//인증 및 validation 검사 authenticationDetailsSource
	@Bean
	public AuthenticationProvider authenticationProvider() {
		return new FormAuthenticationProvider(passwordEncoder());
	}
	
	//패스워드 인코딩 설정
	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	// 인증 매니저 셋팅 - 기본 작성
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	@Override
	protected void configure(final HttpSecurity http) throws Exception {
		http
        .authorizeRequests()
        ;
		
		http
			.formLogin()//폼로그인설정
			.loginPage("/login")
			.loginProcessingUrl("/login_proc")
			.defaultSuccessUrl("/")
			.authenticationDetailsSource(authenticationDetailsSource) // 인증이후에도 이정보들을 참조해서 사용자가 서버자원에 접근 할수 있도록 한다 FormAuthenticationDetailsSource
			.successHandler(formAuthenticationSuccessHandler)
			.failureHandler(formAuthenticationFailureHandler)
			.permitAll();
		http//인가예외
			.exceptionHandling()
			.accessDeniedHandler(accessDeniedHandler())
		.and()
			.addFilterAt(customFilterSecurityInterceptor(), FilterSecurityInterceptor.class) //지정된 필터 보다 커스텀 필터가 먼저 실행 인증완료된 상태이면 인증 로직이 수행되지 않고 자연스럽게 통과 하기 때문에 마치 오버라이드된 것 처럼 동작하는 것으로 착각 할 수 있습니다
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
	/*@Bean
	public FilterSecurityInterceptor customFilterSecurityInterceptor() throws Exception {
		
		FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
		filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
		filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
		filterSecurityInterceptor.setAuthenticationManager(authenticationManagerBean());
		
		return filterSecurityInterceptor;
	}*/
	
	//스프링 시큐리티 기본 설정 클래스 -> 커스텀 // 인가 예외 설정 및 접근 결정자 설정
	//FilterSecurityInterceptor -> PermitAllFilter why? permitAllResources 변수로 허용 url 손쉽게 하려고
	@Bean
    public PermitAllFilter customFilterSecurityInterceptor() throws Exception {

        PermitAllFilter permitAllFilter = new PermitAllFilter(permitAllResources);
        permitAllFilter.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource()); //DB로부터 자원과 자원에대한 권한 정보 저장 및 인가 필터 설정 (init할 떄 설정된 것 가져오는 것으로 보임)
        permitAllFilter.setAccessDecisionManager(affirmativeBased()); // 접근권한매니저 세팅 - 기본 작성
        permitAllFilter.setAuthenticationManager(authenticationManagerBean()); // 인증 매니저 셋팅 - 기본 작성
        return permitAllFilter;
    }

	// 접근권한매니저 세팅 - 기본 작성
	@Bean
	public AccessDecisionManager affirmativeBased() {
		AffirmativeBased affirmativeBased = new AffirmativeBased(getAccessDecistionVoters());
		return affirmativeBased;
	}

	// 접근권한매니저 세팅 - 기본 작성
	private List<AccessDecisionVoter<?>> getAccessDecistionVoters() {
		return Arrays.asList(new RoleVoter());
	}

	//DB로부터 자원 권한 정보 저장
	@Bean
	public UrlFilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {
		return new UrlFilterInvocationSecurityMetadataSource(urlResourcesMapFactoryBean().getObject(), securityResourceService);
	}
	
	private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
		
		UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
		urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
		
		return urlResourcesMapFactoryBean;
	}
	
}
