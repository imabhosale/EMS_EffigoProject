import React, { useState, useEffect } from "react";
import ApiService from "./ApiService";

const ViewDocuments = () => {
  const [files, setFiles] = useState([]);

  useEffect(() => {
    const fetchFiles = async () => {
      try {
        const response = await ApiService.getAllFiles();
        setFiles(response.data);
      } catch (error) {
        console.error("Error fetching files:", error);
      }
    };
    fetchFiles();
  }, []);

  return (
    <div className="container mt-5">
      <h2 className="text-center">Uploaded Documents</h2>
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
