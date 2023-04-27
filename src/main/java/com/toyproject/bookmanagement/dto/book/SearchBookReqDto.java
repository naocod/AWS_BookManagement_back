package com.toyproject.bookmanagement.dto.book;

import java.util.List;

import lombok.Data;

@Data
public class SearchBookReqDto {
	private int page;
	private String searchValue;
	private List<Integer> categoryIds;
}
