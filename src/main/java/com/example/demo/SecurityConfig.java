package com.example.demo;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{

	@Autowired
	private CredentialsService service;
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// TODO Auto-generated method stub
		http.cors().and().csrf().disable().authorizeRequests().anyRequest().authenticated().and().httpBasic();
//		.antMatchers("/**").access("hasRole('ROLE_USER')")
//		.and()
//		  .formLogin().loginPage("/login").failureUrl("/login?error")
//		  .usernameParameter("username").passwordParameter("password")
//		.and()
//		  .logout().logoutSuccessUrl("/login?logout")
//		.and()
//		  .exceptionHandling().accessDeniedPage("/403")
//		.and()
//		  .csrf();
//	      
//	      .and().formLogin().permitAll()
//	      .and().logout().invalidateHttpSession(true)
//	      .clearAuthentication(true).logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
//	      .logoutSuccessUrl("/logout-success").permitAll();
	}
	
	@Bean
	public AuthenticationProvider authProvider()
	{
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(service);
		provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		return provider;
	}
	
	
//	@Bean
//	@Override
//	protected UserDetailsService userDetailsService()
//	{
//		List<UserDetails> users = new ArrayList<>();
//		users.add(User.withDefaultPasswordEncoder().username("shashank").password("12345").roles("USER").build());
//		
//		return new InMemoryUserDetailsManager(users);
//	}
	

	@Bean
    public CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("HEAD",
                "GET", "POST", "PUT", "DELETE", "PATCH"));


        configuration.setAllowCredentials(true);
        // setAllowedHeaders este es importantisimo sion el se lanza el eeror 403 de origenes no permitidos
        //
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
	

}
