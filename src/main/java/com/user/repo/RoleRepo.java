package com.user.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.user.domain.Role;

public interface RoleRepo extends JpaRepository<Role, Long>{

	Role findByName(String rolName);
}
