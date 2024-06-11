package com.example.jwt.filter;

public interface JwtProperties {
    public String SECRET="YourSecretKey"; //  추가
    public String REFRESH_SECRET = "YourRefreshSecretKey"; // 추가
    public int EXPIRATION_TIME=60000*10;
    public  int REFRESH_EXPIRATION_TIME = 7 * 24 * 60 * 60 * 1000; // 추가
    public String TOKEN_PREFIX="Bearer ";
    public String HEADER_STRING="Authorization";
}
