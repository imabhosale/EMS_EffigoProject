import React, { useState } from "react";
import axios from "axios";

export default function UploadCSV() {
  const [csvFile, setCsvFile] = useState(null);
  const [errorMessage, setErrorMessage] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [isUploading, setIsUploading] = useState(false);

  const handleFileChange = (event) => {
    const file = event.target.files[0];

    if (file) {
      const validTypes = ["text/csv", "application/vnd.ms-excel"];
      if (!validTypes.includes(file.type)) {
        setErrorMessage("Only CSV files are allowed.");
        setCsvFile(null);
      } else if (file.size > 5 * 1024 * 1024) { // Limit to 5MB
        setErrorMessage("File size should be under 5MB.");
        setCsvFile(null);
      } else {
        setErrorMessage("");
        setCsvFile(file);
      }
    }
  };

  const handleUpload = async () => {
    if (!csvFile) {
      setErrorMessage("Please select a valid CSV file.");
      return;
    }

    setIsUploading(true);
    setErrorMessage("");
    setSuccessMessage("");

    const token = sessionStorage.getItem("jwtToken");
    const formData = new FormData();
    formData.append("file", csvFile);

    try {
      const response = await axios.post("http://localhost:8999/users/upload", formData, {
        headers: {
          "Content-Type": "multipart/form-data",
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.status === 200) {
        setSuccessMessage("File uploaded successfully!");
        setCsvFile(null);
      } else {
        setErrorMessage(response.data.message || "Error uploading the file.");
      }
    } catch (error) {
      console.error("Upload error: ", error);
      setErrorMessage(
        error.response?.data?.message || "Something went wrong during upload."
      );
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="container" style={{ marginTop: "20px", maxWidth: "500px" }}>
      <h3>Upload CSV</h3>
      <div className="mb-3">
        <input
          type="file"
          className="form-control"
          accept=".csv"
          onChange={handleFileChange}
          disabled={isUploading}
        />
        {csvFile && <p className="text-muted">Selected file: {csvFile.name}</p>}
      </div>
      {errorMessage && <div className="alert alert-danger">{errorMessage}</div>}
      {successMessage && <div className="alert alert-success">{successMessage}</div>}
      <button
        className="btn btn-primary"
        onClick={handleUpload}
        disabled={!csvFile || isUploading}
      >
        {isUploading ? "Uploading..." : "Upload File"}
      </button>
    </div>
  );
}
