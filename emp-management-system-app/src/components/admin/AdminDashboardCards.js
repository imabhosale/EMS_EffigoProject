import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { FaUserCheck, FaUserTimes, FaUserClock, FaBell } from 'react-icons/fa';

// Create an Axios instance with JWT token in headers
const api = axios.create({
  baseURL: 'http://localhost:8999',
});

// Add a request interceptor to include the JWT token
api.interceptors.request.use(
  (config) => {
    const token = sessionStorage.getItem('jwtToken');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

export default function AdminDashboardCards() {
  const [stats, setStats] = useState({
    activeUsers: 0,
    inactiveUsers: 0,
    pendingUsers: 0,
  });
  const [notifications, setNotifications] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const statsResponse = await api.get('/users/stats');
        setStats(statsResponse.data);
      } catch (err) {
        console.error('Error fetching user stats:', err);
        setError('Failed to load user statistics.');
      }

      try {
       // const notificationsResponse = await api.get('/notifications');
      //  setNotifications(notificationsResponse.data);
      } catch (err) {
        console.error('Error fetching notifications:', err);
        setError('Failed to load notifications.');
      }
    };

    fetchData();
  }, []);

  return (
    <div className="row g-3">
      {error && <div className="alert alert-danger">{error}</div>}
      {/* Active Users Card */}
      <div className="col-md-4">
        <div className="card shadow-sm border-0 bg-success text-white">
          <div className="card-body d-flex align-items-center justify-content-between">
            <div>
              <h5 className="card-title">Active Users</h5>
              <h3>{stats.activeUsers}</h3>
            </div>
            <FaUserCheck size={40} />
          </div>
        </div>
      </div>

      {/* Inactive Users Card */}
      <div className="col-md-4">
        <div className="card shadow-sm border-0 bg-secondary text-white">
          <div className="card-body d-flex align-items-center justify-content-between">
            <div>
              <h5 className="card-title">Inactive Users</h5>
              <h3>{stats.inactiveUsers}</h3>
            </div>
            <FaUserTimes size={40} />
          </div>
        </div>
      </div>

      {/* Pending Users Card */}
      <div className="col-md-4">
        <div className="card shadow-sm border-0 bg-warning text-dark">
          <div className="card-body d-flex align-items-center justify-content-between">
            <div>
              <h5 className="card-title">Pending Users</h5>
              <h3>{stats.pendingUsers}</h3>
            </div>
            <FaUserClock size={40} />
          </div>
        </div>
      </div>

      {/* Notifications */}
      <div className="col-md-12">
        <div className="card shadow-sm border-0">
          <div className="card-body">
            <h5 className="card-title d-flex align-items-center">
              <FaBell className="me-2 text-primary" size={24} />
              Notifications
            </h5>
            <ul className="list-group">
              {notifications.length > 0 ? (
                notifications.map((notification, index) => (
                  <li key={index} className="list-group-item">
                    {notification.message}
                  </li>
                ))
              ) : (
                <li className="list-group-item text-muted">No new notifications</li>
              )}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
