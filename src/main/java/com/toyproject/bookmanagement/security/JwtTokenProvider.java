package com.toyproject.bookmanagement.security;

import java.security.Key;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.toyproject.bookmanagement.dto.auth.JwtRespDto;
import com.toyproject.bookmanagement.exception.CustomException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class JwtTokenProvider {
	
	private final Key key;
	
	public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
		key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
	}
	
	public JwtRespDto generateToken(Authentication authentication) {
		
		StringBuilder builder = new StringBuilder();
		
		authentication.getAuthorities().forEach(authority -> {
			builder.append(authority.getAuthority() + ",");
		});
		
		builder.delete(builder.length() - 1, builder.length());	// ROLE_USER, 마지막의 , 삭제
		
		String authorities = builder.toString();
		
		// 1000 > 1초
		Date tokenExpiresDate = new Date(new Date().getTime() + (1000 * 60 * 60 * 24));	// 현재시간 + 하루
		
		String accessToketn = Jwts.builder()
				.setSubject(authentication.getName())		// 토큰의 제목(email) > getName이 email
				.claim("auth", authorities)						// authorities
				.setExpiration(tokenExpiresDate)			// 토큰 만료 시간
				.signWith(key, SignatureAlgorithm.HS256)	// 토큰 암호화
				.compact();
		
		return JwtRespDto.builder().grantType("Bearer").accessToken(accessToketn).build();	// 토큰 리턴
	}
	
	public boolean validateToken(String token) {
		try {
			Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token);
				
			return true;
		} catch (SecurityException | MalformedJwtException e) {
//			log.info("Invalid JWT Token", e);
		} catch (ExpiredJwtException e) {
//			log.info("Expired JWT Token", e);
		} catch (UnsupportedJwtException e) {
//			log.info("Unsupported JET Token", e);
		} catch (IllegalArgumentException e) {
//			log.info("IllegalArgument JWT Token", e);
		} catch (Exception e) {
//			log.info("JWT Token Error", e);
		}
		
		return false;
	}
	
	public String getToken(String token) {
		String type = "Bearer";
		if(StringUtils.hasText(token) && token.startsWith(type)) {
			return token.substring(type.length() + 1);
		}
		
		return null;
		
	}
	
	public Claims getClaims(String token) {
		return Jwts.parserBuilder()
				.setSigningKey(key)
				.build()
				.parseClaimsJws(token)
				.getBody();
	}
	
	public Authentication getAuthentication(String accessToken) {
		Authentication authentication = null;
		
		Claims claims = getClaims(accessToken);
		if(claims.get("auth") == null) {	// 권한 없으면 > null, string으로 바꾸기 전에 객체형태의 null일때 체크
			throw new CustomException("AccessToken에 권한 정보가 없습니다.");
		}
		
		List<SimpleGrantedAuthority> authorities = new ArrayList<>();
		
		String auth = claims.get("auth").toString();
		for(String role : auth.split(",")) {
			authorities.add(new SimpleGrantedAuthority(role));
		}
		
		
		UserDetails userDetails = new User(claims.getSubject(), "", authorities);
		
		authentication = new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
		
		return authentication;
	}
}
