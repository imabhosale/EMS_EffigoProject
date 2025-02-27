package com.ems.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ems.model.Entity.AccessHistory;

public interface AccessHistoryDao extends JpaRepository<AccessHistory, Long>{

}
