import React, { useState } from "react";
import { useParams } from "react-router-dom";
import axios from "axios";

const UploadDocuments = () => {
  const { userId } = useParams();  // Get userId from the URL
  const [file, setFile] = useState(null);
  const [message, setMessage] = useState("");

  const handleFileChange = (event) => {
    setFile(event.target.files[0]);
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!file) {
      setMessage("Please select a file.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      const token = sessionStorage.getItem("jwtToken"); // Get JWT from storage
      if (!token) {
        setMessage("User is not authenticated!");
        return;
      }

      const response = await axios.post(`http://localhost:8999/users/uploadFile/${userId}`, formData, {
        headers: {
          "Content-Type": "multipart/form-data",
          Authorization: `Bearer ${token}`, // Add JWT token in request
        },
      });

      setMessage(response.data);
    } catch (err) {
      setMessage("Error uploading file: " + (err.response?.data?.message || err.message));
    }
  };

  return (
    <div className="container mt-5">
      <h2 className="text-center">Upload Documents for User ID: {userId}</h2>
      {message && <p className="alert alert-info">{message}</p>}
      <form onSubmit={handleSubmit}>
        <div className="mb-3">
          <label className="form-label">Select File:</label>
          <input type="file" className="form-control" onChange={handleFileChange} required />
        </div>
        <button type="submit" className="btn btn-primary">Upload File</button>
      </form>
    </div>
  );
};

export default UploadDocuments;
