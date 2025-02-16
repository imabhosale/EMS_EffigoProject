import React, { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";

const UploadDocuments = () => {
  const { userId } = useParams();  // Get userId from the URL
  const navigate = useNavigate();  // Hook for navigation
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false); // Loading state for button

  const handleFileChange = (event) => {
    setFile(event.target.files[0]);
    setMessage(""); // Clear any previous messages
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    
    if (!file) {
      setMessage("❌ Please select a file before uploading.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      const token = sessionStorage.getItem("jwtToken"); // Get JWT token
      if (!token) {
        setMessage("⚠️ User is not authenticated! Please login again.");
        return;
      }

      setIsLoading(true); // Disable button while uploading

      const { data } = await axios.post(
        `http://localhost:8999/users/uploadFile/${userId}`,
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
            Authorization: `Bearer ${token}`,
          },
        }
      );

      setMessage(`✅ ${data.message || "File uploaded successfully!"} Redirecting...`);

      // Redirect to Admin Dashboard after 2 seconds
      setTimeout(() => {
        navigate("/admin-dashboard/find-all");
      }, 2000);

    } catch (err) {
      setMessage(`❌ Error uploading file: ${err.response?.data?.message || err.message}`);
    } finally {
      setIsLoading(false); // Re-enable button
    }
  };

  return (
    <div className="container mt-5">
      <h2 className="text-center">Upload Documents for User ID: {userId}</h2>
      
      {message && (
        <p className={`alert ${message.includes("✅") ? "alert-success" : "alert-danger"}`}>
          {message}
        </p>
      )}

      <form onSubmit={handleSubmit}>
        <div className="mb-3">
          <label className="form-label">Select File:</label>
          <input type="file" className="form-control" onChange={handleFileChange} required />
        </div>
        
        <button type="submit" className="btn btn-primary" disabled={isLoading}>
          {isLoading ? "Uploading..." : "Upload File"}
        </button>
      </form>
    </div>
  );
};

export default UploadDocuments;
