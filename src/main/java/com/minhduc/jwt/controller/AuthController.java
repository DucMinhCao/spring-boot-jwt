package com.minhduc.jwt.controller;

import com.minhduc.jwt.service.UserService;
import com.minhduc.jwt.shared.dto.UserDto;
import com.minhduc.jwt.ui.model.request.UserDetailsRequestModel;
import com.minhduc.jwt.ui.model.response.UserRest;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

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
}
