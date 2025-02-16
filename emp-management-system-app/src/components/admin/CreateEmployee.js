import { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { API_ENDPOINTS } from "../config/Config";

export default function CreateEmployee() {
  const navigate = useNavigate(); // ✅ Hook for navigation

  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    mobile: "",
    password: "",
    status: "PENDING",
  });

  const [message, setMessage] = useState({ text: "", type: "" });
  const [errors, setErrors] = useState({});

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    setErrors({ ...errors, [e.target.name]: "" }); // ✅ Clear errors when user types
  };

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

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleCreate = async () => {
    if (!validateForm()) {
      setMessage({ text: "Please correct the errors before submitting.", type: "danger" });
      return;
    }

    try {
      const token = sessionStorage.getItem("jwtToken");
      console.log("Token:", token);

      const response = await axios.post(API_ENDPOINTS.CREATE_EMPLOYEE, formData, {
        headers: { Authorization: `Bearer ${token}` },
      });

      console.log("API Response:", response.data);

      setMessage({ text: "User created successfully! Redirecting...", type: "success" });

      // ✅ Wait for 2 seconds, then navigate to the admin dashboard
      setTimeout(() => navigate("/admin-dashboard/find-all"), 2000);
    } catch (error) {
      console.error("Error creating user:", error);

      let errorMessage = "An error occurred.";
      if (error.response) {
        if (error.response.data?.message) {
          errorMessage = error.response.data.message; // Backend error message
        } else if (error.response.status === 409) {
          errorMessage = "Email already exists. Please use a different email.";
        } else {
          errorMessage = `Error ${error.response.status}: ${error.response.statusText}`;
        }
      }
      setMessage({ text: errorMessage, type: "danger" });
    }
  };

  return (
    <div className="card p-4 shadow">
      <h2 className="text-center mb-4">Create User</h2>

      {/* ✅ Display success/error messages */}
      {message.text && (
        <div className={`alert alert-${message.type}`} role="alert">
          {message.text}
        </div>
      )}

      <div className="row g-3">
        <div className="col-md-6">
          <label className="form-label">First Name</label>
          <input
            name="firstName"
            placeholder="First Name"
            value={formData.firstName}
            onChange={handleChange}
            className={`form-control ${errors.firstName ? "is-invalid" : ""}`}
          />
          {errors.firstName && <div className="invalid-feedback">{errors.firstName}</div>}
        </div>

        <div className="col-md-6">
          <label className="form-label">Last Name</label>
          <input
            name="lastName"
            placeholder="Last Name"
            value={formData.lastName}
            onChange={handleChange}
            className={`form-control ${errors.lastName ? "is-invalid" : ""}`}
          />
          {errors.lastName && <div className="invalid-feedback">{errors.lastName}</div>}
        </div>

        <div className="col-md-6">
          <label className="form-label">Email</label>
          <input
            name="email"
            type="email"
            placeholder="Email"
            value={formData.email}
            onChange={handleChange}
            className={`form-control ${errors.email ? "is-invalid" : ""}`}
          />
          {errors.email && <div className="invalid-feedback">{errors.email}</div>}
        </div>

        <div className="col-md-6">
          <label className="form-label">Mobile</label>
          <input
            name="mobile"
            placeholder="Mobile"
            value={formData.mobile}
            onChange={handleChange}
            className={`form-control ${errors.mobile ? "is-invalid" : ""}`}
          />
          {errors.mobile && <div className="invalid-feedback">{errors.mobile}</div>}
        </div>

        <div className="col-md-6">
          <label className="form-label">Password</label>
          <input
            name="password"
            type="password"
            placeholder="Password"
            value={formData.password}
            onChange={handleChange}
            className={`form-control ${errors.password ? "is-invalid" : ""}`}
          />
          {errors.password && <div className="invalid-feedback">{errors.password}</div>}
        </div>

        <div className="col-md-6">
          <label className="form-label">Status</label>
          <select
            name="status"
            value={formData.status}
            onChange={handleChange}
            className="form-select"
          >
            <option value="ACTIVE">ACTIVE</option>
            <option value="INACTIVE">INACTIVE</option>
            <option value="PENDING">PENDING</option>
          </select>
        </div>

        <div className="d-flex justify-content-between mt-3">
          <button onClick={handleCreate} className="btn btn-primary w-50 me-2">
            Create Employee
          </button>
        </div>
      </div>
    </div>
  );
}
