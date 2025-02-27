package com.ems.service;

import com.ems.model.Entity.Role;

public interface RoleService {
	
	Role findByName(String name);
	
}
