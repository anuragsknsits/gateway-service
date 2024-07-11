package com.codewithanurag.apigateway.controller;

import org.springframework.security.web.reactive.result.view.CsrfRequestDataValueProcessor;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
public class CsrfController {

    @GetMapping("/csrf-token")
    public Mono<CsrfToken> csrfToken(ServerWebExchange serverWebExchange) {
        Mono<CsrfToken> csrfToken = serverWebExchange.getAttribute(CsrfToken.class.getName());
        return csrfToken != null ? csrfToken.doOnSuccess(token -> serverWebExchange.getAttributes()
                .put(CsrfRequestDataValueProcessor.DEFAULT_CSRF_ATTR_NAME, token)) : null;
    }
}
