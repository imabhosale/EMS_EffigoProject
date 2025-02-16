import { useEffect, useState } from "react";
import { Routes, Route, useNavigate } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";
import UserSidebar from "./UserSidebar";
import UserHomePage from "./UserHomePage";
import Dashboard from "../Dashboard";
import EditUserProfileOwn from "./EditUserProfileOwn";
import UserProfile from "./UserProfile";
import Chat from "../message/Chat";

export default function UserDashboard() {
  const [userEmail, setUserEmail] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const token = sessionStorage.getItem("jwtToken");

    if (!token) {
      console.error("No token found in UserDashboard, redirecting...");
      navigate("/login");
      return;
    }

    try {
      const decodedToken = JSON.parse(atob(token.split(".")[1])); // Decode JWT
      console.log("Decoded Token:", decodedToken);

      if (!decodedToken || !decodedToken.sub) {
        console.error("Invalid token format, redirecting...");
        navigate("/login");
        return;
      }

      const email = decodedToken.sub; // ✅ Extract email correctly
      setUserEmail(email);

      const roles = decodedToken.roles
        ? decodedToken.roles.split(",").map(role => role.trim())
        : [decodedToken.role || "USER"];

      console.log("User Roles:", roles);

      if (!roles.includes("ROLE_USER")) {
        console.error("User does not have required role, redirecting...");
        navigate("/login");
      }
    } catch (error) {
      console.error("Error decoding token:", error);
      navigate("/login");
    }
  }, [navigate]);

  return (
    <div className="d-flex">
      {/* Sidebar - Fixed Position */}
      <UserSidebar userEmail={userEmail} /> {/* ✅ Pass email to sidebar */}

      {/* Main Content Area */}
      <div className="flex-grow-1 p-4" style={{ marginLeft: "250px" }}>
        

        {/* ✅ Fixed Routing */}
        <Routes>
          <Route path="/" element={<UserHomePage />} />
          {/* <Route path="/dashboard" element={<Dashboard />} /> */}
          <Route path="/profile/:email" element={<UserProfile />} />
          <Route path="/edit/:id" element={<EditUserProfileOwn />} />
          <Route path="chat" element={<Chat/>} />
        </Routes>
      </div>
    </div>
  );
}
