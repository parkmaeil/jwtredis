package com.example.jwt.entity;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class CustomerUser extends User {

    private Customer customer;
    public CustomerUser(Customer customer){                              // USER(String)----|
        super(customer.getUsername(), customer.getPassword(), makeConvertRole(customer.getRoleList())); // GrantedAuthority -> Collection(List)
        this.customer=customer;
    }

    public static Collection<? extends GrantedAuthority> makeConvertRole(List<String> list){
        return list.stream()
                .map(role->new SimpleGrantedAuthority("ROLE_"+role))
                .collect(Collectors.toList());
    }
    public Customer getCustomer() {
        return customer;
    }

    public void setCustomer(Customer customer) {
        this.customer = customer;
    }
}
