import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { jwtDecode } from "jwt-decode";
import "bootstrap/dist/css/bootstrap.min.css"; // Import Bootstrap CSS

export default function Login({ setIsLoggedIn }) {
  const [formData, setFormData] = useState({ email: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleLogin = async () => {
    if (!formData.email || !formData.password) {
      setError("Email and Password are required");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await fetch("http://localhost:8999/users/authenticate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.message || "Invalid Email or Password");
        return;
      }

      alert("Login successful!");
      sessionStorage.setItem("jwtToken", data.token);
      setIsLoggedIn(true);

      // Decode token to extract roles
      const decodedToken = jwtDecode(data.token);
      const userRoles = decodedToken.roles
        ? decodedToken.roles.split(",")
        : [decodedToken.role || "USER"];

      const trimmedRoles = userRoles.map((role) => role.trim());
      console.log("User Roles:", trimmedRoles);

      // Redirect based on roles
      if (trimmedRoles.includes("ROLE_ADMIN")) {
        navigate("/admin-dashboard");
      } else if (trimmedRoles.includes("ROLE_USER")) {
        navigate("/user-dashboard");
      } else {
        setError("⚠️ Invalid role assigned. Contact support.");
      }
    } catch (error) {
      console.error("Login error:", error);
      setError("Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container d-flex justify-content-center align-items-center vh-100">
      <div className="card shadow-lg p-4" style={{ width: "350px" }}>
        <h2 className="text-center mb-3">Login</h2>

        {error && <div className="alert alert-danger">{error}</div>}

        <div className="mb-3">
          <label className="form-label">Email</label>
          <input
            name="email"
            type="email"
            placeholder="Enter your email"
            value={formData.email}
            onChange={handleChange}
            className="form-control"
          />
        </div>

        <div className="mb-3">
          <label className="form-label">Password</label>
          <input
            name="password"
            type="password"
            placeholder="Enter your password"
            value={formData.password}
            onChange={handleChange}
            className="form-control"
          />
        </div>

        <button
          onClick={handleLogin}
          className="btn btn-primary w-100"
          disabled={loading}
        >
          {loading ? (
            <>
              <span
                className="spinner-border spinner-border-sm"
                role="status"
                aria-hidden="true"
              ></span>{" "}
              Logging in...
            </>
          ) : (
            "Login"
          )}
        </button>
      </div>
    </div>
  );
}
