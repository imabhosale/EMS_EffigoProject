import React from "react";
import { Routes, Route } from "react-router-dom";
import AdminSidebar from "./AdminSidebar";
import AllUserList from "./AllUserList";
import useAuth from "./useAuth";
import CreateEmployee from "./CreateEmployee";
import FindUser from "./FindUser";
import UploadCSV from "./UploadCSV";
import EditUserProfile from "./EditUserProfile";
import ManageUserApproval from "./ManageUserApproval";
import UploadDocuments from "./UploadDocuments";
import AdminDashboardCards from "./AdminDashboardCards";
import Chat from "../message/Chat";
import AccessHistoryTable from "./AccessHistoryTable";
import ViewDocuments from "../ViewDocuments";

export default function AdminDashboard() {
  useAuth("ROLE_ADMIN");
  return (
    <div className="d-flex">
      <AdminSidebar />
      
      <div className="flex-grow-1" style={{ marginLeft: "250px", padding: "20px" }}>
        

        <Routes>
        <Route path="/" element={<AdminDashboardCards />} />
          <Route path="create-employee" element={<CreateEmployee />} />
          <Route path="find-user" element={<FindUser />} />
          <Route path="find-all" element={<AllUserList />} />
          <Route path="edit/:userId" element={<EditUserProfile />} />
          <Route path="admin-approvals" element={<ManageUserApproval />} />
          <Route path="upload-csv" element={<UploadCSV />} />
          <Route path="chat" element={<Chat/>} />
          <Route path="upload-documents/:userId" element={<UploadDocuments />} />
          <Route path="view-documents/:userId" element={<ViewDocuments />} />
          <Route path="accessHistory" element={<AccessHistoryTable/>}/>
        </Routes>
      </div>
    </div>
  );
}
