import React, { useEffect, useState } from "react";
import axios from "axios";
import { FaUserCheck, FaUserTimes, FaUserClock } from "react-icons/fa"; // Icons

export default function UserStats() {
  const [stats, setStats] = useState({
    activeUsers: 0,
    inactiveUsers: 0,
    pendingUsers: 0,
  });

  useEffect(() => {
    axios.get("http://localhost:8999/find/all") // Adjust API endpoint as needed
      .then(response => {
        const users = response.data;

        // Count users based on status
        const active = users.filter(user => user.status === "ACTIVE").length;
        const inactive = users.filter(user => user.status === "INACTIVE").length;
        const pending = users.filter(user => user.status === "PENDING").length;

        setStats({ activeUsers: active, inactiveUsers: inactive, pendingUsers: pending });
      })
      .catch(error => console.error("Error fetching user data:", error));
  }, []);

  return (
    <div className="row g-3">
      {/* Active Users */}
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

      {/* Inactive Users */}
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

      {/* Pending Users */}
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
    </div>
  );
}
