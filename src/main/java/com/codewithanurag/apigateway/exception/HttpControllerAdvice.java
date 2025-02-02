package com.codewithanurag.apigateway.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class HttpControllerAdvice {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> getException(Exception ex) {
        ex.fillInStackTrace();
        return ResponseEntity.badRequest().body(ex.getMessage());
    }
}
