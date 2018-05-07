package com.computerspace.hotelspace;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private AccessDeniedHandler accessDeniedHandler;
	
	@Override//definimos acceso
	protected void configure(HttpSecurity http) throws Exception {
		
		http.csrf().disable()
		       .authorizeRequests()
		       .antMatchers("/marketing").hasAnyRole("MARKETING")
		       
		       .antMatchers("/desarrollo").hasAnyRole("DESARROLLO")
		       .antMatchers("/").permitAll()
		       .antMatchers("/admin").hasAnyRole("ADMIN")
		      // .antMatchers("/").hasAnyRole("USER")
		       .anyRequest().authenticated()
		       .and()
		       .formLogin()
		       .loginProcessingUrl("/milogin").usernameParameter("app_user").passwordParameter("app_contra").defaultSuccessUrl("/habitaciones")
		       //.loginPage("/login")
		       .permitAll()
		       .and()
		       .logout()
		       .permitAll().logoutRequestMatcher(new AntPathRequestMatcher("/logout")).logoutSuccessUrl("/")
		       .and()
		       .exceptionHandling().accessDeniedHandler(accessDeniedHandler);
		
		

}
@Autowired//definimos usuarios
public void configureGlobal (AuthenticationManagerBuilder auth)
                       throws Exception{
	
	BCryptPasswordEncoder encoder = passwordEncoder();
	auth.inMemoryAuthentication()
	           // .withUser("user").password(encoder.encode("1234")).roles("USER")
	           // .and()	
	          //  .withUser("user2").password(encoder.encode("1111")).roles("USER")
	            .withUser("desarrollo").password(encoder.encode("1111")).roles("DESARROLLO")
	            .and()	
	            .withUser("marketing").password(encoder.encode("1111")).roles("MARKETING")
	            .and()
	            .withUser("admin").password(encoder.encode("password")).roles("ADMIN");
}

@Bean
public BCryptPasswordEncoder passwordEncoder() {
	return new BCryptPasswordEncoder ();
}
}
