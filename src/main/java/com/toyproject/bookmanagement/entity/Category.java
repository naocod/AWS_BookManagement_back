package com.toyproject.bookmanagement.entity;

import com.toyproject.bookmanagement.dto.book.CategoryRespDto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class Category {
	private int categoryId;
	private String categoryName;
	
	public CategoryRespDto toDto() {
		return CategoryRespDto.builder()
				.categoryId(categoryId)
				.categoryName(categoryName)
				.build();
	}
}
