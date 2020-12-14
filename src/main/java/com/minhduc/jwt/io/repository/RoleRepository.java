package com.minhduc.jwt.io.repository;

import com.minhduc.jwt.io.entity.Role;
import com.minhduc.jwt.io.entity.RoleEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleEnum(RoleEnum roleEnum);
}
