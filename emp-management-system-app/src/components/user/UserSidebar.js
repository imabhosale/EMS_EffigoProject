import React from "react";
import { Link } from "react-router-dom";

export default function UserSidebar({ userEmail }) {
  return (
    <div className="bg-dark text-white vh-100 p-3" style={{ width: "250px", position: "fixed" }}>
      <h4>User Panel</h4>
      <ul className="nav flex-column">
        <li className="nav-item">
          <Link className="nav-link text-white" to="/user-dashboard/dashboard">Dashboard</Link>
        </li>
        {userEmail ? (
          <li className="nav-item">
            <Link className="nav-link text-white" to={`/user-dashboard/profile/${encodeURIComponent(userEmail)}`}>
              View Profile
            </Link>
          </li>
        ) : (
          <li className="nav-item">
            <span className="nav-link text-muted">Loading...</span>
          </li>
        )}
        <li className="nav-item">
          <Link className="nav-link text-white" to="/user-dashboard/user-tasks">My Tasks</Link>
        </li>
      </ul>
    </div>
  );
}
