import { useState, useEffect } from "react";
import { Routes, Route } from "react-router-dom";  

import Hero from "./components/Hero";
import Header from "./components/Header";
import Login from "./components/Login";
import Register from "./components/Register";
import AdminDashboard from "./components/admin/AdminDashboard";

// User Components
import UserDashboard from "./components/user/UserDashboard";
import EditUserProfileOwn from "./components/user/EditUserProfileOwn";

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    const token = sessionStorage.getItem("jwtToken");
    setIsLoggedIn(!!token);
  }, []);

  return (
    <>
      <Header isLoggedIn={isLoggedIn} setIsLoggedIn={setIsLoggedIn} />
      
      <Routes>
          <Route path="/" element={<Hero/>} />
          <Route path="/login" element={<Login setIsLoggedIn={setIsLoggedIn} />} />
          <Route path="/register" element={<Register />} />

          <Route path="/user-dashboard/profile/view-documents" element={<EditUserProfileOwn showDocumentsOnLoad={true} />} />

          
          <Route path="/admin-dashboard/*" element={<AdminDashboard />} />
          <Route path="/user-dashboard/*" element={<UserDashboard />} />
          <Route path="/user-dashboard" element={<UserDashboard />} />
    </Routes>

    </>
  );
}

export default App;
