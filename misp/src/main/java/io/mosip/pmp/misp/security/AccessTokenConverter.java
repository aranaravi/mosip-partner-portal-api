package io.mosip.pmp.misp.security;

import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.List;
import java.util.ArrayList;

@Component
public class AccessTokenConverter extends JwtAccessTokenConverter {

    private static final String RESOURCE_CLAIM = "resource_access";
    private static final String ROLES = "roles";
    private static final String ROLE_PREFIX = "ROLE_";
    private static final String AUTHORITIES = "authorities";
    private static final JsonParser JSON_PARSER = JsonParserFactory.create();    

    @Override
    public Map<String, Object> decode(String token) {
        Jwt jwt = JwtHelper.decode(token);
        Map<String, Object> claims = JSON_PARSER.parseMap(jwt.getClaims());
        if (claims.containsKey(EXP) && claims.get(EXP) instanceof Integer) {
            Integer expiryInt = (Integer) claims.get(EXP);
            claims.put(EXP, new Long(expiryInt));
        }
        this.getJwtClaimsSetVerifier().verify(claims);
        List<String> userRoles = new ArrayList<String>();       
        Map<String, Object> resource_access = (Map)claims.get(RESOURCE_CLAIM);
        resource_access.forEach((clientKey, clientRole) -> {
            List<String> roleList = (List<String>)((Map)((Map)
                        claims.get(RESOURCE_CLAIM)).get(clientKey)).get(ROLES);
            roleList.forEach (role -> {
                userRoles.add(ROLE_PREFIX + role);
            });
        });
        claims.put(AUTHORITIES, userRoles); 
        return claims;
    }
}