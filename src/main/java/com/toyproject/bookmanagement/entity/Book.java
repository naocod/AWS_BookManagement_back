package com.toyproject.bookmanagement.entity;

import com.toyproject.bookmanagement.dto.book.GetBookRespDto;
import com.toyproject.bookmanagement.dto.book.SearchBookRespDto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
public class Book {
	private int bookId;
	private String bookName;
	private int authorId;
	private int publisherId;
	private int categoryId;
	private String coverImgUrl;
	private int likeCount;
	
	private Author author;
	private Publisher publisher;
	private Category category;
	
	public SearchBookRespDto toDto() {
		return SearchBookRespDto.builder()
				.bookId(bookId)
				.bookName(bookName)
				.authorId(authorId)
				.authorName(author.getAuthorName())
				.publisherId(publisherId)
				.publisherName(publisher.getPublisherName())
				.categoryId(categoryId)
				.categoryName(category.getCategoryName())
				.coverImgUrl(coverImgUrl)
				.likeCount(likeCount)
				.build();
	}
	
	public GetBookRespDto toGetBookDto() {
		return GetBookRespDto.builder()
				.bookId(bookId)
				.bookName(bookName)
				.authorName(author.getAuthorName())
				.publisherName(publisher.getPublisherName())
				.categoryName(category.getCategoryName())
				.coverImgUrl(coverImgUrl)
				.build();
	}
}
