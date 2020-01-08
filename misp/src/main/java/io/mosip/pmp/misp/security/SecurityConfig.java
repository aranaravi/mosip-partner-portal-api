package io.mosip.pmp.misp.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@EnableOAuth2Sso
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
  	protected void configure(HttpSecurity http) throws Exception {
	    http
	      .authorizeRequests()
          .antMatchers("/pmp/misps").hasRole("admin")
          .antMatchers("/pmp/misps/**").hasRole("user") 
          .antMatchers("/error**")
          .permitAll()
	      .anyRequest()
          .authenticated();
  	}
}
