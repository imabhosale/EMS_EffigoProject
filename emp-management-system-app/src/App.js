import { useState, useEffect } from "react";
import { Routes, Route } from "react-router-dom";  // ❌ No need to import `Router`

import Hero from "./components/Hero";
import Dashboard from "./components/Dashboard";
import Header from "./components/Header";
import Login from "./components/Login";
import Register from "./components/Register";
import Footer from "./components/Footer";
import AdminDashboard from "./components/admin/AdminDashboard";

// User Components
import UserDashboard from "./components/user/UserDashboard";

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
  <Route path="/" element={<Hero />} />
  <Route path="/login" element={<Login setIsLoggedIn={setIsLoggedIn} />} />
  <Route path="/dashboard" element={<Dashboard />} />
  <Route path="/register" element={<Register />} />

  {/* ✅ Fix: Change /admin-dashboard to /admin */}
  <Route path="/admin-dashboard/*" element={<AdminDashboard />} />
  <Route path="/user-dashboard/*" element={<UserDashboard />} />
  <Route path="/user-dashboard" element={<UserDashboard />} />
</Routes>

      <Footer />
    </>
  );
}

export default App;
