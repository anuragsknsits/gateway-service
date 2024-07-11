package com.codewithanurag.apigateway.filter;

import com.codewithanurag.apigateway.util.JWTUtil;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
public class JwtFilter extends AbstractGatewayFilterFactory<JwtFilter.Config> {

    private final JWTUtil jwtUtil;
    private final RouteValidator validator;

    public JwtFilter(JWTUtil jwtUtil, RouteValidator validator) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
        this.validator = validator;
    }

    @Override
    public GatewayFilter apply(JwtFilter.Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            validateToken(request);
            HttpCookie httpCookie = request.getCookies().getFirst("X-XSRF-TOKEN");
            if (httpCookie != null) {
                ServerHttpRequest modifiedRequest = request.mutate().header("X-XSRF-TOKEN", httpCookie.getValue()).build();
                return chain.filter(exchange.mutate().request(modifiedRequest).build());
            }
            return chain.filter(exchange);
        });
    }

    private void validateToken(ServerHttpRequest request) {
        if (validator.isSecured.test(request)) {
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing authorization header");
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                authHeader = authHeader.substring(7);
            }
            try {
                jwtUtil.validateToken(authHeader);
            } catch (Exception e) {
                System.out.println("Invalid access...!");
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized access to the application");
            }
        }
    }

    public static class Config {
    }
}
