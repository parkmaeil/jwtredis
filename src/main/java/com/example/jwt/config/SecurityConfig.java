package com.example.jwt.config;

import com.example.jwt.filter.JwtAuthenticationFilter;
import com.example.jwt.filter.JwtAuthorizationFilter;
import com.example.jwt.service.CustomerService;
import com.example.jwt.service.RedisService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {
    @Autowired
    private CorsConfig corsConfig;
    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    private final RedisService redisService;
    private final CustomerService customerService;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        // JWT 서버구현 : React.js 프론트 구성(로그폼 UI X, 인증방식,(토큰) - ID,PWD, 세션X)
        // 서버(백엔드)<-----CORS(정책)----->서버(React.js)
        // CSRF(form - CSRF 토큰을 넘기게 되어있다. JWT를 사용할때는 CSRF 토큰을 넘기지 않겠다)
        http.csrf(csrf->csrf.disable())
                .sessionManagement(sm->sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(form->form.disable())
                .httpBasic(hb -> hb.disable())
                .authorizeHttpRequests(authz->authz
                        .requestMatchers("/api/v1/user/**").hasAnyRole("USER","MANAGER","ADMIN")
                        .requestMatchers("/api/v1/manager/**").hasAnyRole("MANAGER","ADMIN")
                        .requestMatchers("/api/v1/admin/**").hasAnyRole("ADMIN")
                        .anyRequest().permitAll()
                )
                // CORS(정책) - 필터를 가지고 있는 객체를 만들기
                //.addFilter(crosFilter());
                .apply(new MyCustomerDSL());

            return http.build();
    }
    // 사용자정의 DSL(Domain Specific Language)
    public class MyCustomerDSL extends AbstractHttpConfigurer<MyCustomerDSL , HttpSecurity>{
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager=http.getSharedObject(AuthenticationManager.class);
                http
                        .addFilter(corsConfig.corsFilter())
                       // 추가적인 필터 2개를 등록....
                        .addFilter(new JwtAuthenticationFilter(authenticationManager, redisService)) // AuthenticationManager
                        .addFilter(new JwtAuthorizationFilter(authenticationManager, customerService, redisService));
        }
    }
}
