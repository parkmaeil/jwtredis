package com.example.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.entity.Customer;
import com.example.jwt.entity.CustomerUser;
import com.example.jwt.service.CustomerService;
import com.example.jwt.service.RedisService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

@RequiredArgsConstructor                                   //  http://localhost:8081/login - username, password
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    // 로그인 시도!!
    private AuthenticationManager authenticationManager;
    private RedisService redisService;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager,
                                   RedisService redisService) {
        this.authenticationManager=authenticationManager;
        this.redisService=redisService;
    }
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter : 로그인 시도중...");
        // AuthenticationManager --> PrincipalDetailsService 객체의 loadUserByUsername()메서드를 실행....
        // Authentication 객체생성 -> SecurityContextHolder(등록) --> View 사용 ~~~
        // JWT 토큰 생성
        // 1. form, 2. json(문자열) --> IO(BufferedReader), ObjectMapper(객체=Customer)
        try{
            /*BufferedReader br=request.getReader();
            String input=null;
            while((input=br.readLine())!=null){
                System.out.println(input); // ?
            }*/
             ObjectMapper objectMapper=new ObjectMapper();
             Customer customer=objectMapper.readValue(request.getInputStream(), Customer.class);
             System.out.println(customer); // ?
            //  username, password->
            UsernamePasswordAuthenticationToken authenticationToken=
                    new UsernamePasswordAuthenticationToken(customer.getUsername(), customer.getPassword());
            // PrincipalDetailsService -> loadUserByUsername() 실행된다.
            Authentication authentication=authenticationManager.authenticate(authenticationToken);
            CustomerUser customerUser = (CustomerUser) authentication.getPrincipal();
            // 인증에 성공후 Authentication 개에 안에 저장된 정보를 얻어서 출력
            System.out.println(customerUser.getUsername());
            return  authentication; // SecurityContextHolder -> 권한처리
            // 데이터베이스 인증처리~~~ JWT 토큰 발행?
        }catch(Exception e){
            e.printStackTrace();
        }
        return null;
    }
    // attemptAuthentication() -->  successfulAuthentication() 호출
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // JTW 토큰 생성 -> 클라이언트에 헤더로 잔달을 해준다.
        System.out.println("successfulAuthentication 실행됨~~");
        CustomerUser customerUser= (CustomerUser) authResult.getPrincipal();
        String jwtToken= JWT.create()
                .withSubject("JWT 토큰")
                .withExpiresAt(new Date(System.currentTimeMillis()+(JwtProperties.EXPIRATION_TIME))) // 10분 만료시간 -> 고려?
                .withClaim("id", customerUser.getCustomer().getId())
                .withClaim("username", customerUser.getCustomer().getUsername())
                // 권한정보(List->Array->String[]
                .withArrayClaim("authorities", customerUser.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .toArray(String[]::new) // [  ROLE_USER, ROLE_MANAGER, ROLE_ADMIN  ]
                )
                .sign(Algorithm.HMAC256(JwtProperties.SECRET)); // cosin 암호화


        String newRefreshToken = JWT.create()
                .withSubject("JWT 토큰")
                .withExpiresAt(new Date(System.currentTimeMillis()+(JwtProperties.REFRESH_EXPIRATION_TIME))) // 10분 만료시간 -> 고려?
                .withClaim("id", customerUser.getCustomer().getId())
                .withClaim("username", customerUser.getCustomer().getUsername())
                // 권한정보(List->Array->String[]
                .withArrayClaim("authorities", customerUser.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .toArray(String[]::new) // [  ROLE_USER, ROLE_MANAGER, ROLE_ADMIN  ]
                )
                .sign(Algorithm.HMAC256(JwtProperties.REFRESH_SECRET)); // cosin 암호화
                redisService.saveRefreshToken(customerUser.getCustomer().getUsername(), newRefreshToken);

                response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwtToken);    // 포스트멘에서 확인
                                                      // Authorization(권한)
    }
}
