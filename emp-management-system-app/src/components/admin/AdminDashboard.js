// AdminDashboard.js
import React from "react";
import { Routes, Route, useNavigate } from "react-router-dom";
import AdminSidebar from "./AdminSidebar";
import AllUserList from "./AllUserList"; 
import useAuth from "./useAuth";
import CreateEmployee from "./CreateEmployee";
import FindUser from "./FindUser";
import ManageUsers from "./ManageUsers";
import UploadCSV from "./UploadCSV"; // Import the new component
import EditUserProfile from "./EditUserProfile";
import ManageUserApproval from "./ManageUserApproval";
import UploadDocuments from "./UploadDocuments";
import ViewDocuments from "./ViewDocuments";

export default function AdminDashboard() {
  useAuth("ROLE_ADMIN"); // Ensure only Admin can access this page
  const navigate = useNavigate();

  return (
    <div className="d-flex">
      {/* Fixed Sidebar */}
      <AdminSidebar />

      {/* Main Content */}
      <div className="flex-grow-1" style={{ marginLeft: "250px", padding: "20px" }}>
        {/* <h2>Admin Dashboard</h2> */}

        {/* Admin Action Buttons */}
        {/* <div className="mb-4">
          <button className="btn btn-primary me-2" onClick={() => navigate("/admin-dashboard/create-employee")}>
            Create Employee
          </button>
          <button className="btn btn-success me-2" onClick={() => navigate("/admin-dashboard/find-user")}>
            Find User
          </button>
          <button className="btn btn-danger" onClick={() => navigate("/admin-dashboard/manage-users")}>
            Manage Users
          </button>
        </div> */}

        {/* Routes for Admin Pages */}
        <Routes>
          <Route path="create-employee" element={<CreateEmployee />} />
          <Route path="find-user" element={<FindUser />} />
          <Route path="find-all" element={<AllUserList />} />
          <Route path="edit/:userId" element={<EditUserProfile />} />

          <Route path="admin-approvals" element={<ManageUserApproval/>} />
    
          <Route path="manage-users" element={<ManageUsers />} />
          <Route path="upload-csv" element={<UploadCSV />} /> 
          
          <Route path="upload-documents/:userId" element={<UploadDocuments />} />
        <Route path="view-documents/:userId" element={<ViewDocuments />} />
           </Routes>
      </div>
    </div>
  );
}
