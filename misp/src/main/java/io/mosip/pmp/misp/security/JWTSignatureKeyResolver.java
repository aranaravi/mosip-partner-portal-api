package io.mosip.pmp.misp.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SigningKeyResolver;

import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.util.Base64Utils;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Component
public class JWTSignatureKeyResolver implements SigningKeyResolver {

    private final String x509Cert;    

    public JWTSignatureKeyResolver(Environment env) {
        this.x509Cert = env.getProperty("security.oauth2.resource.jwt.key-value");
    }

    @Override    
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        return extractPublicKey(this.x509Cert);
    }

    @Override
    public Key resolveSigningKey(JwsHeader header, String plaintext) {
        return resolveSigningKey(header, (Claims) null);
    }

    private PublicKey extractPublicKey(String x509Certificate) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            InputStream certStream = new ByteArrayInputStream(Base64Utils.decodeFromString(x509Certificate));
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certStream);
            return certificate.getPublicKey();
        } catch (CertificateException e) {            
            throw new SecurityException("Unable to parse the certificate.");
        }
    }
}

