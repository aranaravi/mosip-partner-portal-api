package io.mosip.pmp.misp.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.beans.factory.annotation.Value;

@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter { 
    
    @Value("${security.oauth2.client.client-id}")
    private String clientId;

    @Autowired
    JwtAccessTokenConverter converter;

    @Override
    public void configure(ResourceServerSecurityConfigurer config) {
        config.tokenServices(tokenServices()).resourceId(clientId);
    }

    @Bean
    public JwtAccessTokenConverter jwtTokenEnhancer() {        
        return converter;
    }

    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setSupportRefreshToken(true);
        return defaultTokenServices;
    }
    
    @Bean
    public TokenStore tokenStore() {
        DefaultUserAuthenticationConverter userAuthConverter = new DefaultUserAuthenticationConverter();
        DefaultAccessTokenConverter accessTokenConverter = (DefaultAccessTokenConverter) 
                    converter.getAccessTokenConverter();
        accessTokenConverter.setUserTokenConverter(userAuthConverter);
        return new JwtTokenStore(converter);
    }
}