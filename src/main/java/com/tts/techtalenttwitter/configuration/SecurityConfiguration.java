package com.tts.techtalenttwitter.configuration;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter{
	
	private DataSource dataSource;
	
	@Autowired
	private BCryptPasswordEncoder bCryptPasswordEncoder;
// We are configuring Spring Security. This is a config class that is provided by Spring Security. By default it sets Spring Security up in a lock down config 
	//By inheriting and overriding certain methods we can config Spring Secuirty to be confg differently.
	
	
	@Value("${spring.queries.users-query")
	private String usersQuery;
	
	@Value("${spring.queries.roles-query}")
	private String rolesQuery;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.jdbcAuthentication()
		
		.usersByUsernameQuery(usersQuery)
		.authoritiesByUsernameQuery(rolesQuery)
		.dataSource(dataSource)
		.passwordEncoder(bCryptPasswordEncoder);
		
		
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception{
		http.authorizeRequests()
			.antMatchers("console/**").permitAll()
			.antMatchers("/login").permitAll()
			.antMatchers("/signup").permitAll()
			.antMatchers("/custom.js").permitAll()
			.antMatchers("/custom.css").permitAll()
			.antMatchers().hasAuthority("USER").anyRequest().authenticated()
		.and()
			.formLogin() //This tells spring security that we are going to log in using a webpage that has a form.
				.loginPage("/login").failureUrl("/login?error=true")
				.defaultSuccessUrl("/tweets")
				.usernameParameter("username")
				.passwordParameter("password")
				
		.and()
			.logout()
			.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
			.logoutSuccessUrl("/login")
		.and()
			.exceptionHandling()
		.and()
			.csrf().disable()
			.headers().frameOptions().disable();
		
		
	}
	
	@Override
	public void configure(WebSecurity web) throws Exception{
		web.ignoring().antMatchers("/resources/**", "/static/**", "/css/**", "/js/**", "/images/**");
	}
	
	
	
}
