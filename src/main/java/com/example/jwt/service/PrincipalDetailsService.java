package com.example.jwt.service;

import com.example.jwt.entity.Customer;
import com.example.jwt.entity.CustomerUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Service;

@Service // 추가
public class PrincipalDetailsService implements UserDetailsService {
    @Autowired
    private CustomerService customerService;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Customer customer=customerService.findByUsername(username);
        return new CustomerUser(customer); // CustomerUser<---User
    }
}
/*
  ID, PWD --> /login --> UsernamePasswordAuthenticationFilter -->  PrincipalDetailsService(loadUserByUsername)

 */
