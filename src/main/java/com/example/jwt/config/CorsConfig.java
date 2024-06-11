package com.example.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {
    @Bean
    public CorsFilter corsFilter(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();// CORS 구성 등록, 관리
        CorsConfiguration config = new CorsConfiguration(); // CORS 구성객체
        config.setAllowCredentials(true); // CORS 요청을 허용
        config.addAllowedOrigin("*"); // 모든요청 *
        config.addAllowedHeader("*"); // 모든헤더 *
        config.addAllowedMethod("*");// 모든메서드 요청 *
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }

}
