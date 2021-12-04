package com.user.service.impl;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.user.domain.Role;
import com.user.domain.User;
import com.user.repo.RoleRepo;
import com.user.repo.UserRepo;
import com.user.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserServiceImpl implements UserService, UserDetailsService {

	private final UserRepo userRepo;
	private final RoleRepo roleRepo;
	private final PasswordEncoder passwordEncoder;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		User user = userRepo.findByUsername(username);
		if(user == null) {
			log.error("User not found in the database");
			throw new UsernameNotFoundException("User not found in the database");
		}else {
			log.info("user found in the database {} ", username);
		}
		Collection<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
		authorities = user.getRoles().stream()
		.map(x -> new SimpleGrantedAuthority(x.getName()))
		.collect(Collectors.toList());
		System.out.println(authorities);
		return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
	}

	@Override
	public User saveUser(User user) {
		// TODO Auto-generated method stub
		log.info("saving new user {} to the database ", user.getUsername());
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		Role role = roleRepo.findByName("ROLE_USER");
		user.getRoles().add(role);
		return userRepo.save(user);
	}

	@Override
	public Role saveRole(Role role) {
		// TODO Auto-generated method stub
		log.info("saving new user {} to the database ", role.getName());
		return roleRepo.save(role);
	}

	@Override
	public void addRoleToUser(String username, String roleName) {
		// TODO Auto-generated method stub
		log.info("add role {} to user {} ", roleName, username);
		User user = userRepo.findByUsername(username);
		Role role = roleRepo.findByName(roleName);
		if (user != null && role != null)
			user.getRoles().add(role);
		userRepo.save(user);
	}

	@Override
	public User getUser(String username) {
		// TODO Auto-generated method stub
		log.info("fetching  user {} ", username);
		return userRepo.findByUsername(username);
	}

	@Override
	public List<User> getUsers() {
		// TODO Auto-generated method stub
		log.info("fetching all users");
		return userRepo.findAll();
	}

}
