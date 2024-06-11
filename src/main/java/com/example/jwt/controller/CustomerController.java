package com.example.jwt.controller;

import com.example.jwt.entity.Customer;
import com.example.jwt.entity.CustomerUser;
import com.example.jwt.service.CustomerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CustomerController {

    @Autowired
    private CustomerService customerService;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @PostMapping("/join")
    public String join(@RequestBody Customer customer){
          customer.setPassword(passwordEncoder.encode(customer.getPassword()));
          customer.setRoles("USER"); // ROLE_USER
          customerService.register(customer); // 등록
          return "success";
    }
}
