package com.toyproject.bookmanagement.dto.auth;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.toyproject.bookmanagement.entity.User;

import lombok.Data;

@Data
public class SignupReqDto {
	
	@Email
	@NotBlank(message = "이메일을 입력하세요.")	// 이메일 형식인지만 확인하기 때문에 NotBlank를 걸어줘야함
	private String email;
	
	
	// 정규식
	// ^ 시작 $ 끝
	// ()[] 각각의 그룹 -> 모든 조건이 True여야함
	// 그룹 정규식 
	// (?=.*[A-Za-z]) ?= 앞쪽이 일치하는 지 확인 .* 모든글자 [] 범위가 대문자 A-Z 소문자 a-z
	// 모든글자 중에서 대문자 A-Z 소문자 a-z를 포함하고 있는지 확인
	// .*\\d 모든 숫자 === .*[0-9]
	// [@$!%*#?&] 특수문자 하나 포함
	// [A-Za-z\\d@$!%*#?&] 포함할 수 있는 글자(허용 범위)
	// {8,} 글자 갯수 8자 이상 == {8,16} 최대값은 16글자 생략
	@Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,}$",
			message = "비밀번호는 영문자, 숫자, 특수문자를 포함하여 8 ~ 16자로 작성하세요.")
	private String password;
	
	// 한글 외에는 받지 않음, 글자수 2~7자 제한
	@Pattern(regexp = "^[가-힣]{2,7}$",
			message = "한글 이름만 작성 가능합니다.")
	private String name;
	
	public User toEntity() {
		return User.builder()
				.email(email)
				.password(new BCryptPasswordEncoder().encode(password))
				.name(name)
				.build();
	}
}
