package com.ems.service.serviceImpl;

import java.time.LocalDateTime;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ems.model.AccessHistory;
import com.ems.repository.AccessHistoryDao;


@Service
public class AccessHistoryServiceImpl {
	@Autowired
	AccessHistoryDao accessHistoryDao;
	
	final Boolean LOGIN = true;
	final Boolean LOGOUT = false;
	
	public void loggedIn(Long userId, LocalDateTime time) {
		accessHistoryDao.save(new AccessHistory(userId, time, LOGIN));
	}
	
	public void loggedOut(Long userId, LocalDateTime time) {
		accessHistoryDao.save(new AccessHistory(userId, time, LOGOUT));
	}

	public List<AccessHistory> getAllHistory() {
		return accessHistoryDao.findAll();
	}
}
