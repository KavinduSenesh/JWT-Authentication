package lk.ijse.springJwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lk.ijse.springJwt.model.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {
    private final String SECRET_KEY = "a3f8e4b3004f10691346553f87afaaeddf77751918dbca6afa72bed72b0ea0b8ad043a0efb4a8738d200157b3d3a6c82265660e15cf8a26cffe4111d2f22312bbbb24ffbf984a30ceea6b53eafc85d590ff49ffbbe4f94c894f8e3483b1c8f5e4db1951af2db300411049852b52db8d594de3f4874336d155eb3e3c24750d0127d2829a5b938dc76f5c31de5eb12cd4284b0e772b338cad0ad5fa1c720b98da0b3d1c180ed0899b74acf32cdc7593a8044d89f9fcbde7c9a177646b140dc59c471866510c9de68cdd8f48c2646e28b7230ce70f683d6639300c72ce87e87cf5b909bc45d63ca54d2b2534dfaea9857377203ea9df759448f1bd40e9b3268e498";

    public String extractUsername(String token) {
        return extractClaims(token, Claims::getSubject);
    }

    public boolean isValid(String token, UserDetails user) {
        String username = extractUsername(token);
        return (username.equals(user.getUsername()) && !isTokenExpired(token)) ;
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    public <T> T extractClaims(String token, Function<Claims, T> resolver) {
        Claims claims = extractAllClaims(token);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parser()
                .verifyWith(getSigninKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String generateToken(User user) {
        String token = Jwts
                .builder()
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 24*60*60*1000))
                .signWith(getSigninKey())
                .compact();
        return token;
    }

    private SecretKey getSigninKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
