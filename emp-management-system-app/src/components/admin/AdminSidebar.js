import React from "react";
import { Link } from "react-router-dom";

export default function AdminSidebar() {
  return (
    <div className="bg-dark text-white vh-100 p-3" style={{ width: "250px", position: "fixed" }}>
      <h4>Admin Panel</h4>
      <ul className="nav flex-column">
      <li className="nav-item">
          <Link className="nav-link text-white" to="/admin-dashboard/find-all">Find All Users</Link>
        </li>
        <li className="nav-item">
          <Link className="nav-link text-white" to="/admin-dashboard/dashboard">Dashboard</Link>
        </li>
        <li className="nav-item">
          <Link className="nav-link text-white" to="/admin-dashboard/create-employee">Create Employee</Link>
        </li>
        <li className="nav-item">
          <Link className="nav-link text-white" to="/admin-dashboard/find-user">Find User</Link>
        </li>
        <li className="nav-item">
          <Link className="nav-link text-white" to="/admin-dashboard/manage-users">Manage Users</Link>
        </li>
      </ul>
    </div>
  );
}
