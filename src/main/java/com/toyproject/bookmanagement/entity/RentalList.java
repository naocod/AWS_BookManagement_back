package com.toyproject.bookmanagement.entity;

import com.toyproject.bookmanagement.dto.book.RentalListRespDto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class RentalList {
	private int bookListId;
	private String bookName;
	private int userId;
	
	public RentalListRespDto toDto() {
		return RentalListRespDto.builder()
				.bookListId(bookListId)
				.bookName(bookName)
				.userId(userId)
				.rentalStatus(userId == 0)	// true - 렌탈 가능, false - 렌탈 불가능
				.build();
	}

}

