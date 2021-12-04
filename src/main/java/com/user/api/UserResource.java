package com.user.api;

import java.io.IOException;
import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.user.domain.Role;
import com.user.domain.User;
import com.user.dto.RoleToUserForm;
import com.user.service.UserService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/v1")
public class UserResource {

	private final UserService userService;

	@Secured(value = {"ROLE_ADMIN", "ROLE_SUPER_ADMIN"})
	@GetMapping("/users")
	public ResponseEntity<?> getUsers() {
		return ResponseEntity.ok().body(userService.getUsers());
	}

	@PreAuthorize("isAuthenticated()")
	@GetMapping("/user")
	public ResponseEntity<?> getUser() {
		SecurityContext securityContext = SecurityContextHolder.getContext();
		String username = securityContext.getAuthentication().getName();
		return ResponseEntity.ok().body(userService.getUser(username));
	}
	
	@Secured(value = {"ROLE_ADMIN", "ROLE_SUPER_ADMIN"})
	@PostMapping("/user/save")
	public ResponseEntity<?> saveUser(@RequestBody User user) {
		URI uri = URI
				.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/v1/user/save").toUriString());
		return ResponseEntity.created(uri).body(userService.saveUser(user));
	}

	@Secured(value = {"ROLE_ADMIN", "ROLE_SUPER_ADMIN"})
	@PostMapping("/role/save")
	public ResponseEntity<?> saveRole(@RequestBody Role role) {
		URI uri = URI
				.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/v1/role/save").toUriString());
		return ResponseEntity.created(uri).body(userService.saveRole(role));
	}

	@Secured(value = {"ROLE_ADMIN", "ROLE_SUPER_ADMIN"})
	@PostMapping("/role/addToUser")
	public ResponseEntity<?> saveRoleToUser(@RequestBody RoleToUserForm roleToUserForm) {
		userService.addRoleToUser(roleToUserForm.getUsername(), roleToUserForm.getRoleName());
		return ResponseEntity.ok().build();
	}

	@PostMapping("/token/refresh")
	public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
		String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
			try {
				String refreshToken = authorizationHeader.substring(7);
				Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
				JWTVerifier verifier = JWT.require(algorithm).build();
				DecodedJWT decodedJWT = verifier.verify(refreshToken);
				String username = decodedJWT.getSubject();
				User user = userService.getUser(username);
				
				List<String> authorities = user.getRoles().stream().map(Role::getName)
						.collect(Collectors.toList());
				String accessToken = JWT.create().withSubject(user.getUsername())
						.withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
						.withIssuer(request.getRequestURI().toString()).withClaim("roles", authorities).sign(algorithm);

				Map<String, String> tokens = new HashMap<String, String>();
				tokens.put("access_token", accessToken);
				tokens.put("refresh_token", refreshToken);
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				new ObjectMapper().writeValue(response.getOutputStream(), tokens);
				
			} catch (Exception e) {
				Map<String, String> error = new HashMap<String, String>();
				error.put("error_message", e.getMessage());
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				new ObjectMapper().writeValue(response.getOutputStream(), error);
			}
		} else {
			throw new RuntimeException("Refresh token is missing");
		}
		return ResponseEntity.ok().build();
	}
}
