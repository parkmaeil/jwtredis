package com.example.jwt.repository;

import com.example.jwt.entity.Customer;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CustomerRepository extends JpaRepository<Customer, Long> {
    public Customer findByUsername(String username);
}
