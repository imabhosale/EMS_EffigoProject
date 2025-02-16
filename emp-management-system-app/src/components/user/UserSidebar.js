import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";

export default function UserSidebar({ userEmail }) {
  const [userRoles, setUserRoles] = useState([]);

  useEffect(() => {
    const token = sessionStorage.getItem("jwtToken");
    if (token) {
      const tokenPayload = JSON.parse(atob(token.split(".")[1])); // Decode JWT
      console.log("Decoded Token Payload:", tokenPayload);

      if (tokenPayload.roles) {
        const rolesArray = tokenPayload.roles.split(",").map(role => role.trim()); // Trim spaces
        console.log("Extracted Roles:", rolesArray);
        setUserRoles(rolesArray);
      }
    }
  }, []);

  console.log("Rendering Sidebar - Current Roles:", userRoles); // Check roles in render

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
          <Link className="nav-link text-white" to="/user-dashboard/chat">Chat</Link>
        </li>

        {/* Show "Back to Admin Dashboard" only if the user has ROLE_ADMIN */}
        {userRoles.includes("ROLE_ADMIN") && (
          <li className="nav-item">
            <Link className="nav-link text-white" to="/admin-dashboard">
                Admin Dashboard  ⬅️
            </Link>
          </li>

        )}
      </ul>
    </div>
  );
}
