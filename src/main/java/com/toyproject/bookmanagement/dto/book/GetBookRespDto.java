package com.toyproject.bookmanagement.dto.book;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class GetBookRespDto {
	private int bookId;
	private String bookName;
	private String authorName;
	private String publisherName;
	private String categoryName;
	private String coverImgUrl;

}
