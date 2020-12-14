package com.minhduc.jwt.service.impl;

import com.minhduc.jwt.io.entity.Role;
import com.minhduc.jwt.io.entity.RoleEnum;
import com.minhduc.jwt.io.entity.User;
import com.minhduc.jwt.io.repository.RoleRepository;
import com.minhduc.jwt.io.repository.UserRepository;
import com.minhduc.jwt.service.UserService;
import com.minhduc.jwt.shared.dto.UserDto;
import com.minhduc.jwt.shared.utils.UserDetailsBuilder;
import com.minhduc.jwt.shared.utils.Util;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {

    private UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    private RoleRepository roleRepository;
    private Util util;

    public UserServiceImpl(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder, Util util, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.util = util;
        this.roleRepository = roleRepository;
    }

    @Override
    public UserDto createUser(UserDto userDto) {
        if (userRepository.findByEmail(userDto.getEmail()) != null) {
            throw new RuntimeException("User Existed!");
        }
//
        ModelMapper mapper = new ModelMapper();
//        User userEntity = mapper.map(user, User.class);

        User userEntity = new User();
        userEntity.setFirstName(userDto.getFirstName());
        userEntity.setLastName(userDto.getLastName());
        userEntity.setEmail(userDto.getEmail());

        for (String r : userDto.getRole()) {
            Role role = roleRepository.findByRoleEnum(RoleEnum.valueOf(r)).orElseThrow(() -> new RuntimeException());
            userEntity.getRoles().add(role);
        }

        String publicUserId = util.generateUserId(20);
        userEntity.setUserId(publicUserId);
        userEntity.setEncryptedPassword(bCryptPasswordEncoder.encode(userDto.getPassword()));

        User storedUser = userRepository.save(userEntity);
        UserDto returnValue = mapper.map(storedUser, UserDto.class);
        return returnValue;
    }

    @Override
    public UserDto getUser(String email) {
        UserDto returnValue = new UserDto();
        ModelMapper mapper = new ModelMapper();

        returnValue = mapper.map(userRepository.findByEmail(email), UserDto.class);
        return returnValue;
    }

    @Override
    public UserDto getUserByUserId(String userId) {
        return null;
    }

    @Override
    public UserDto updateUser(String userId, UserDto user) {
        return null;
    }

    @Override
    public void deleteUser(String userId) {

    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User userEntity = userRepository.findByEmail(email);

        if (userEntity == null)
            throw new UsernameNotFoundException(email);

        UserDetailsBuilder userDetailsBuilder = UserDetailsBuilder.build(userEntity);
        return userDetailsBuilder;
    }
}
