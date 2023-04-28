package com.toyproject.bookmanagement.dto.book;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class RentalListRespDto {
	private int bookListId;
	private String bookName;
	private int userId;
	private boolean rentalStatus;
}
