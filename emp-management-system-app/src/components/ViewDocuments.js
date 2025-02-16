import React, { useState, useEffect } from "react";
import { useParams } from "react-router-dom";
import axios from "axios";

const ViewDocuments = () => {
  const { userId } = useParams(); // Email is used as userId
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchFiles = async () => {
      try {
        const token = sessionStorage.getItem("jwtToken");
        if (!token) {
          setError("User is not authenticated.");
          return;
        }

        const response = await axios.get(`http://localhost:8999/users/find/${encodeURIComponent(userId)}`, {
          headers: { Authorization: `Bearer ${token}` },
        });

        setFiles(response.data);
      } catch (err) {
        setError("Error fetching files.");
        console.error("Error fetching files:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchFiles();
  }, [userId]);

  if (loading) return <p className="text-center mt-4">Loading documents...</p>;
  if (error) return <p className="text-center mt-4 text-danger">{error}</p>;

  return (
    <div className="container mt-5">
      <h2 className="text-center">User Documents</h2>
      {files.length === 0 ? (
        <p className="text-center">No files uploaded yet.</p>
      ) : (
        <div className="list-group">
          {files.map((file) => (
            <a key={file.id} href={file.fileUrl} target="_blank" rel="noopener noreferrer" className="list-group-item list-group-item-action">
              {file.name}
            </a>
          ))}
        </div>
      )}
    </div>
  );
};

export default ViewDocuments;
