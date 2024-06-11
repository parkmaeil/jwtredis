package com.example.jwt.service;

import com.example.jwt.entity.Customer;
import com.example.jwt.repository.CustomerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CustomerService {

    @Autowired
    private CustomerRepository customerRepository;

    public Customer findByUsername(String username){
        return customerRepository.findByUsername(username);
    }

    public void register(Customer customer){
         customerRepository.save(customer);
    }
}
