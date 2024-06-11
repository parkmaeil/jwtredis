package com.example.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.example.jwt.entity.Customer;
import com.example.jwt.entity.CustomerUser;
import com.example.jwt.service.CustomerService;
import com.example.jwt.service.RedisService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private CustomerService customerService;
    private RedisService redisService;
    public JwtAuthorizationFilter(AuthenticationManager authenticationManager,
                                  CustomerService customerService, RedisService redisService) {
        super(authenticationManager);
        this.customerService=customerService;
        this.redisService=redisService;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 요청들은 이부분을 실행하게 된다.");
        // JWT 토큰을 받아보자.
        String jwtHeader=request.getHeader("Authorization");
        System.out.println("jwtToken:" + jwtHeader); //
        if(jwtHeader==null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request, response);
            return;
        }
        // 정상적인 JWT 토큰이면....
        String jwtToken=request.getHeader("Authorization").replace("Bearer ","");
        // cosin
        try {
            String username = JWT.require(Algorithm.HMAC256(JwtProperties.SECRET))
                    .build()
                    .verify(jwtToken).getClaim("username")
                    .asString();
            if (username != null) {
                Customer customer = customerService.findByUsername(username);
                CustomerUser customerUser = new CustomerUser(customer);
                Authentication authentication = new UsernamePasswordAuthenticationToken(customerUser, null, customerUser.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
                chain.doFilter(request, response);
                return;
            }
        }catch(JWTVerificationException e){
              handleExpiredToken(request, response, chain, jwtToken);
        }
    }

    private void handleExpiredToken(HttpServletRequest request, HttpServletResponse response, FilterChain chain, String expiredJwtToken) throws IOException, ServletException {
        String username = JWT.decode(expiredJwtToken).getClaim("username").asString();
        if (username != null) {
            // Retrieve the refresh token from Redis using the username as the key
            String storedRefreshToken = redisService.getRefreshToken(username);
            if (storedRefreshToken != null) {
                try {
                    // Verify the refresh token
                    JWTVerifier verifier = JWT.require(Algorithm.HMAC256(JwtProperties.REFRESH_SECRET)).build();
                    verifier.verify(storedRefreshToken);

                    // Generate a new access token
                    String newAccessToken = generateAccessToken(username);
                    response.addHeader("Authorization", JwtProperties.TOKEN_PREFIX + newAccessToken);

                    // Authenticate the user and proceed with the request
                    Customer customer = customerService.findByUsername(username);
                    CustomerUser customerUser = new CustomerUser(customer);
                    Authentication authentication = new UsernamePasswordAuthenticationToken(customerUser, null, customerUser.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    chain.doFilter(request, response);
                    return;
                } catch (JWTVerificationException ex) {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid refresh token");
                    return;
                }
            }
        }
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token is expired or invalid");
    }
    private String generateAccessToken(String username) {
        Customer customer = customerService.findByUsername(username);
        CustomerUser customerUser = new CustomerUser(customer);

        return JWT.create()
                .withSubject("JWT 토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME))
                .withClaim("id", customerUser.getCustomer().getId())
                .withClaim("username", username)
                .withArrayClaim("authorities", customerUser.getAuthorities()
                        .stream()
                        .map(grantedAuthority -> grantedAuthority.getAuthority())
                        .toArray(String[]::new))
                .sign(Algorithm.HMAC256(JwtProperties.SECRET));
    }
}
