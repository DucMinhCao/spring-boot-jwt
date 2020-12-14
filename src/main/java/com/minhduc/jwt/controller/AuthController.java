package com.minhduc.jwt.controller;

import com.minhduc.jwt.constant.SecurityConstants;
import com.minhduc.jwt.service.UserService;
import com.minhduc.jwt.shared.dto.UserDto;
import com.minhduc.jwt.ui.model.request.UserDetailsRequestModel;
import com.minhduc.jwt.ui.model.request.UserLoginRequestModel;
import com.minhduc.jwt.ui.model.response.UserRest;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
public class AuthController {

    private UserService userService;
    private AuthenticationManager authenticationManager;

    public AuthController(UserService userService, AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/register")
    public UserRest createUser(@RequestBody UserDetailsRequestModel userDetailsRequestModel) {
        ModelMapper mapper = new ModelMapper();
        UserDto userDto = mapper.map(userDetailsRequestModel, UserDto.class);

        userDto.getRole().add("ROLE_USER");

        UserDto createdUser = userService.createUser(userDto);
        UserRest returnValue = mapper.map(createdUser, UserRest.class);
        return returnValue;
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody UserLoginRequestModel userLoginRequestModel) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userLoginRequestModel.getEmail(), userLoginRequestModel.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = Jwts.builder()
                .setSubject(userLoginRequestModel.getEmail())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + SecurityConstants.EXPIRATION_TIME))
                .signWith(SignatureAlgorithm.HS512, SecurityConstants.getTokenSecret())
                .compact();

        return ResponseEntity.ok(jwt);
    }
}
