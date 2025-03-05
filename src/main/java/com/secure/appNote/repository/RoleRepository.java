package com.secure.appNote.repository;

import com.secure.appNote.models.AppRole;
import com.secure.appNote.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(AppRole appRole);

}
