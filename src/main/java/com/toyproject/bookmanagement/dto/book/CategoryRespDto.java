package com.toyproject.bookmanagement.dto.book;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class CategoryRespDto {
	private int categoryId;
	private String categoryName;
}
