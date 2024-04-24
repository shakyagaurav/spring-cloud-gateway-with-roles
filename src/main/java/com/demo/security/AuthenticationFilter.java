package com.demo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@RefreshScope
@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final String BEARER_TYPE = "Bearer ";

    @Autowired
    private RouterValidator validator;

    @Autowired
    private  JwtUtil jwtUtil;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = null;
            if (validator.isSecured.test(exchange.getRequest())) {

                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    return handleErrorRequest(exchange, HttpStatus.UNAUTHORIZED);
                }

                String authHeader = Objects.requireNonNull(exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION)).get(0);
                if (authHeader != null && authHeader.startsWith(BEARER_TYPE)) {
                    authHeader = authHeader.substring(7);
                }
                Claims claims = jwtUtil.getAllClaimsFromToken(authHeader);
                try {
                    if(validator.isAdministrative.test(exchange.getRequest())){
                        List<String> roles = (List<String>) claims.get("roles");
                        if(!roles.contains(config.getRoles())){
                            return handleErrorRequest(exchange, HttpStatus.FORBIDDEN);
                        }
                    }
                }
                catch (ExpiredJwtException e){
                    return handleErrorRequest(exchange, HttpStatus.UNAUTHORIZED);
                }
                 request = exchange.getRequest()
                        .mutate()
                        .header("username", claims.getSubject())
                        .build();
            }
            return chain.filter(exchange.mutate().request(request).build());
        });
    }

    private Mono<Void> handleErrorRequest(ServerWebExchange exchange, HttpStatus status){
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        return response.setComplete();
    }

    public static class Config {
        private String roles;

        public String getRoles() {
            return roles;
        }

        public void setRoles(String roles) {
            this.roles = roles;
        }
    }

    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("roles");
    }
}
