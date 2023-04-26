package com.toyproject.bookmanagement.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer{
	
	@Override
	public void addCorsMappings(CorsRegistry registry) {
		registry.addMapping("/**")
			.allowedMethods("*")
			.allowedOrigins("*");	// 모든 요청 포트 허용 >> test할떄만 사용
//			.allowedOrigins("http://localhost:3000");	// 3000포트에서 날라온 모든 요청을 다 열어줌 -> @CrossOrigin CORS에러에 특정 url에 대한 허가를 위한 어노테이션
	}

}
