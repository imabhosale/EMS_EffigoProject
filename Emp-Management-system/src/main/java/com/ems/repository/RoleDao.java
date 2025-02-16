package com.ems.repository;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.ems.model.Role;

import jakarta.transaction.Transactional;

@Repository
public interface RoleDao extends JpaRepository<Role, Long> {
    Role findRoleByName(String name);
    
    
    @Modifying
    @Transactional
    @Query(value = "INSERT INTO user_roles (user_id, role_id) " +
                   "SELECT :userId, 1 WHERE NOT EXISTS " +
                   "(SELECT 1 FROM user_roles WHERE role_id = 1 AND user_id = :userId)", nativeQuery = true)
    void makeUserAdmin(Long userId);
}