import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";

export default function Register() {
  const navigate = useNavigate(); // Hook for navigation

  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    mobile: "",
    password: "",
    // status: "",
  });

  const [errors, setErrors] = useState({});
  const [toast, setToast] = useState({ show: false, message: "", type: "" });

  const validateForm = () => {
    let newErrors = {};

    if (!formData.firstName.trim()) newErrors.firstName = "First Name is required";
    if (!formData.lastName.trim()) newErrors.lastName = "Last Name is required";
    if (!formData.password.trim()) newErrors.password = "Password is required";

    if (!formData.email.trim()) {
      newErrors.email = "Email is required";
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = "Invalid email format";
    }

    if (!formData.mobile.trim()) {
      newErrors.mobile = "Mobile number is required";
    } else if (!/^\d{10}$/.test(formData.mobile)) {
      newErrors.mobile = "Mobile number must be 10 digits";
    }

    if (!formData.status) newErrors.status = "Status is required";

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    setErrors({ ...errors, [e.target.name]: "" });
  };

  const showToast = (message, type) => {
    setToast({ show: true, message, type });

    setTimeout(() => {
      setToast({ show: false, message: "", type: "" });
    }, 3000);
  };

  const handleRegister = async () => {
    if (!validateForm()) {
      showToast("Please correct the errors before submitting.", "danger");
      return;
    }

    try {
      const response = await fetch("http://localhost:8999/users/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      });

      const data = await response.json();
      if (response.ok) {
        showToast("Registration successful! Redirecting to login...", "success");
        setTimeout(() => navigate("/login"), 3000);
      } else {
        showToast(data.message || "Registration failed. Try again.", "danger");
      }
    } catch (error) {
      console.error("Registration error:", error);
      showToast("Something went wrong. Please try again later.", "danger");
    }
  };

  return (
    <div className="container d-flex justify-content-center align-items-center vh-100">
      <div className="card shadow-lg p-4 w-50">
        <h2 className="text-center mb-3">Register</h2>

        {/* Bootstrap Toast (Position Adjusted Below Header) */}
        <div
          className={`toast align-items-center text-bg-${toast.type} position-fixed end-0 m-3 p-2 ${toast.show ? "show" : "hide"}`}
          style={{ top: "80px", right: "20px", zIndex: 1050 }} 
          role="alert"
          aria-live="assertive"
          aria-atomic="true"
        >
          <div className="d-flex">
            <div className="toast-body">{toast.message}</div>
            <button type="button" className="btn-close me-2 m-auto" onClick={() => setToast({ show: false })}></button>
          </div>
        </div>

        <div className="row">
          {/* Left Column */}
          <div className="col-md-6">
            <div className="mb-3">
              <label className="form-label">First Name</label>
              <input
                name="firstName"
                placeholder="Enter first name"
                value={formData.firstName}
                onChange={handleChange}
                className={`form-control ${errors.firstName ? "is-invalid" : ""}`}
              />
              {errors.firstName && <div className="invalid-feedback">{errors.firstName}</div>}
            </div>

            <div className="mb-3">
              <label className="form-label">Email</label>
              <input
                name="email"
                type="email"
                placeholder="Enter email"
                value={formData.email}
                onChange={handleChange}
                className={`form-control ${errors.email ? "is-invalid" : ""}`}
              />
              {errors.email && <div className="invalid-feedback">{errors.email}</div>}
            </div>

            <div className="mb-3">
              <label className="form-label">Password</label>
              <input
                name="password"
                type="password"
                placeholder="Enter password"
                value={formData.password}
                onChange={handleChange}
                className={`form-control ${errors.password ? "is-invalid" : ""}`}
              />
              {errors.password && <div className="invalid-feedback">{errors.password}</div>}
            </div>
          </div>

          {/* Right Column */}
          <div className="col-md-6">
            <div className="mb-3">
              <label className="form-label">Last Name</label>
              <input
                name="lastName"
                placeholder="Enter last name"
                value={formData.lastName}
                onChange={handleChange}
                className={`form-control ${errors.lastName ? "is-invalid" : ""}`}
              />
              {errors.lastName && <div className="invalid-feedback">{errors.lastName}</div>}
            </div>

            <div className="mb-3">
              <label className="form-label">Mobile</label>
              <input
                name="mobile"
                type="tel"
                placeholder="Enter mobile number"
                value={formData.mobile}
                onChange={handleChange}
                className={`form-control ${errors.mobile ? "is-invalid" : ""}`}
              />
              {errors.mobile && <div className="invalid-feedback">{errors.mobile}</div>}
            </div>

            <div className="mb-3">
              <label className="form-label">Status</label>
              <select
                name="status"
                value={formData.status}
                onChange={handleChange}
                className={`form-select ${errors.status ? "is-invalid" : ""}`}
              >
                <option value="">Select Status</option>
                <option value="ACTIVE">ACTIVE</option>
                <option value="PENDING">PENDING</option>
                <option value="INACTIVE">INACTIVE</option>
              </select>
              {errors.status && <div className="invalid-feedback">{errors.status}</div>}
            </div>
          </div>
        </div>

        <button onClick={handleRegister} className="btn btn-success w-100">
          Register
        </button>

        <p className="text-center mt-3">
          Already have an account? <a href="/login">Login</a>
        </p>
      </div>
    </div>
  );
}
