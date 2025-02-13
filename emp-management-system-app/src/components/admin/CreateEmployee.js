import { useState } from "react";
import axios from "axios";
import { API_ENDPOINTS } from "../config/Config";

export default function CreateEmployee({ fetchUsers = () => {} }) {
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    mobile: "",
    password: "",
    status: "PENDING",
  });

  const [message, setMessage] = useState({ text: "", type: "" });

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleCreate = async () => {
    try {
      const token = sessionStorage.getItem("jwtToken");
      console.log("Token:", token);

      const response = await axios.post(API_ENDPOINTS.CREATE_EMPLOYEE, formData, {
        headers: { Authorization: `Bearer ${token}` },
      });

      console.log("API Response:", response.data);

      setMessage({ text: "User created successfully!", type: "success" });

      // Clear form
      setFormData({
        firstName: "",
        lastName: "",
        email: "",
        mobile: "",
        password: "",
        status: "PENDING",
      });

      fetchUsers();
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

      {/* ✅ Display error messages */}
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
            className="form-control"
          />
        </div>

        <div className="col-md-6">
          <label className="form-label">Last Name</label>
          <input
            name="lastName"
            placeholder="Last Name"
            value={formData.lastName}
            onChange={handleChange}
            className="form-control"
          />
        </div>

        <div className="col-md-6">
          <label className="form-label">Email</label>
          <input
            name="email"
            type="email"
            placeholder="Email"
            value={formData.email}
            onChange={handleChange}
            className="form-control"
          />
        </div>

        <div className="col-md-6">
          <label className="form-label">Mobile</label>
          <input
            name="mobile"
            placeholder="Mobile"
            value={formData.mobile}
            onChange={handleChange}
            className="form-control"
          />
        </div>

        <div className="col-md-6">
          <label className="form-label">Password</label>
          <input
            name="password"
            type="password"
            placeholder="Password"
            value={formData.password}
            onChange={handleChange}
            className="form-control"
          />
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
