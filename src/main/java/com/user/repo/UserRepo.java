package com.user.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.user.domain.User;

public interface UserRepo extends JpaRepository<User, Long>{

	User findByUsername(String username);
}
