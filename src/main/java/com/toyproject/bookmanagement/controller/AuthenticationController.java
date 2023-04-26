package com.toyproject.bookmanagement.controller;

import javax.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.toyproject.bookmanagement.aop.annotation.ValidAspect;
import com.toyproject.bookmanagement.dto.auth.LoginReqDto;
import com.toyproject.bookmanagement.dto.auth.SignupReqDto;
import com.toyproject.bookmanagement.service.AuthenticationService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {
	
	private final AuthenticationService authenticationService;
	
	@ValidAspect
	@PostMapping("/login")
	public ResponseEntity<?> login(@Valid @RequestBody LoginReqDto loginReqDto, BindingResult bindingResult) {
//		System.out.println(loginReqDto);
//		authenticationService.signin(loginReqDto); // 토큰 가져옴
		return ResponseEntity.ok(authenticationService.signin(loginReqDto));
	}
	
//	@CrossOrigin > config에서 포트 전체 허용
	@ValidAspect
	@PostMapping("/signup")
	public ResponseEntity<?> signup(@Valid @RequestBody SignupReqDto signupReqDto, BindingResult bindingResult) {
		authenticationService.checkDuplicatedEmail(signupReqDto.getEmail());
		authenticationService.signup(signupReqDto);
		return ResponseEntity.ok().body(true);
	}
	
	@GetMapping("/authenticated")
	public ResponseEntity<?> authenticated(String accessToken) {
		
		return ResponseEntity.ok().body(authenticationService.authenticated(accessToken));
	}
	
	@GetMapping("/principal")
	public ResponseEntity<?> principal(String accessToken) {
		return ResponseEntity.ok().body(authenticationService.getPrincipal(accessToken));
	}
}
