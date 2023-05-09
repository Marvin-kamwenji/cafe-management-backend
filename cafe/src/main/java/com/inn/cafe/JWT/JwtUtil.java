package com.inn.cafe.JWT;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JwtUtil {
    private String secret = "marvin";


/*===========================================================================*/
/*========== Extracting username from the jwt token =========================*/
/*===========================================================================*/
    public String extractUsername(String token){
        return extractClaims(token, Claims::getSubject);
    }

/*===========================================================================*/
/*========== Extracting expiration time from the jwt token ==================*/
/*===========================================================================*/
    public Date extractExpiration(String token){
        return extractClaims(token, Claims::getExpiration);
    }


    public <T> T extractClaims(String token, Function<Claims, T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token){
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }

/* ======================================================================================= */
/* ================================Generating jwt token ================================== */
/* ======================================================================================== */
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))  //token will expire in 10 hours
                .signWith(SignatureAlgorithm.HS256, secret).compact(); //generates token
    }

    public String generateToken(String username, String role){
        Map<String,Object> claims = new HashMap<>();
        claims.put("role", role);
        return createToken(claims,username);
    }

/*==========================================================================================*/
/* ==================Checking if token provided has expired ================================*/
/* ======================================================================================== */
    private Boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

/* ======================================================================================== */
/* ======================== Checking if token is valid =====================================*/
/* =========================================================================================*/
    public Boolean validateToken(String token, UserDetails userDetails){
//        Extracting username
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
