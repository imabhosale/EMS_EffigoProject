import { Link, useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { jwtDecode } from "jwt-decode";
import "bootstrap/dist/css/bootstrap.min.css"; // Ensure Bootstrap is imported

const Header = ({ isLoggedIn, setIsLoggedIn }) => {
  const navigate = useNavigate();
  const [userName, setUserName] = useState("");

  useEffect(() => {
    const token = sessionStorage.getItem("jwtToken");
    if (token) {
      try {
        const decodedToken = jwtDecode(token);
        setUserName(decodedToken.name || "User"); // Default to "User" if name is missing
      } catch (error) {
        console.error("Invalid token:", error);
        sessionStorage.removeItem("jwtToken");
        setIsLoggedIn(false);
      }
    }
  }, [isLoggedIn]); // Re-run when login state changes

  const handleLogout = () => {
    const confirmLogout = window.confirm("Are you sure you want to log out?");
    if (!confirmLogout) return;
    sessionStorage.removeItem("jwtToken");
    setIsLoggedIn(false);
    navigate("/login");
  };

  return (
    <header className="bg-dark text-white p-3" style={{ position: "sticky", top: 0, zIndex: 1000 }}>
      <div className="d-flex justify-content-between align-items-center">
        <h2 className="m-0">Employee Management App</h2>
        <nav>
          {isLoggedIn ? (
            <div className="d-flex align-items-center">
              <span className="me-3">Welcome, {userName}</span>
              <button
                onClick={handleLogout}
                className="btn btn-danger btn-sm"
                style={{ transition: "background-color 0.3s ease" }}
              >
                Logout
              </button>
            </div>
          ) : (
            <div className="d-flex">
              <Link
                to="/login"
                className="btn btn-primary me-3"
                style={{ transition: "background-color 0.3s ease" }}
              >
                Login
              </Link>
              <Link
                to="/register"
                className="btn btn-success"
                style={{ transition: "background-color 0.3s ease" }}
              >
                Register
              </Link>
            </div>
          )}
        </nav>
      </div>
    </header>
  );
};

export default Header;
