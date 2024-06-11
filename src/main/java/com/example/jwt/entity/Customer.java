package com.example.jwt.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.Data;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Data
@Entity
public class Customer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String password;
    // 한명의 회원이 여러개의 권한을 가질수있다.(N) - Customer
    //                                                                             member_roles(관계테이블)
    // 하나의 권한은 여러명의 회원이 가질수있다.(N) - Role
    private String roles; // 권한 : "ROLE_USER, ROLE_MANAGER, ROLE_ADMIN" , "USER, MANAGER"
    public List<String> getRoleList(){
        if(this.roles.length()>0){
             return Arrays.asList(roles.split(","));
        }
        return new ArrayList<>();
    }
}
