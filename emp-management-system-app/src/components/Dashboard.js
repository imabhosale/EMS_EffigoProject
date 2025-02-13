import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { jwtDecode } from "jwt-decode";
import AdminDashboard from "./admin/AdminDashboard";
import UserDashboard from "./user/UserDashboard";
import "bootstrap/dist/css/bootstrap.min.css";

export default function Dashboard() {
  const [role, setRole] = useState("USER");
  const [username, setUsername] = useState("User");
  const navigate = useNavigate();

  useEffect(() => {
    const token = sessionStorage.getItem("jwtToken");

    if (!token) {
      console.warn("No token found, redirecting...");
      navigate("/login");
      return;
    }

    try {
      const decodedToken = jwtDecode(token);
      console.log("Decoded Token:", decodedToken);

      setUsername(decodedToken.sub || "User");

      let roles = decodedToken.roles || "";
      if (typeof roles === "string") {
        roles = roles.split(",");
      }

      console.log("User Roles:", roles);

      if (roles.includes("ROLE_ADMIN")) setRole("ADMIN");
      else setRole("USER");
    } catch (error) {
      console.error("Error decoding token:", error);
      localStorage.removeItem("jwtToken");
      navigate("/login");
    }
  }, [navigate]);

  const handleLogout = () => {
    localStorage.removeItem("jwtToken");
    navigate("/login");
  };

  return (
    <div className="container d-flex justify-content-center align-items-center min-vh-100 bg-light">
      <div className="card shadow-lg border-0 rounded-4 p-4" style={{ width: "450px" }}>
        <div className="card-body text-center">
          <h2 className="card-title text-primary fw-bold mb-3">Welcome, {username} 👋</h2>
          <p className="text-muted">This is your professional dashboard.</p>

          {/* Role-based dashboard */}
          <div className="mt-4">
            {role === "ADMIN" && <AdminDashboard />}
            {role === "USER" && <UserDashboard />}
          </div>

          <button
            onClick={handleLogout}
            className="btn btn-danger w-100 mt-4 fw-semibold"
          >
            Logout
          </button>
        </div>
      </div>
    </div>
  );
}
