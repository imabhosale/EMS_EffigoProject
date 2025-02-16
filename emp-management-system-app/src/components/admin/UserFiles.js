import { useState } from "react";
import { FaFileAlt } from "react-icons/fa";

export default function UserFiles({ files }) {
  const [selectedFile, setSelectedFile] = useState("");

  if (!files || files.length === 0) {
    return <p className="text-muted">No files uploaded yet.</p>;
  }

  return (
    <div className="mt-4">
      <h5>Total Files Uploaded: {files.length}</h5>
      <div className="d-flex flex-wrap gap-3">
        {files.map((file) => (
          <div key={file.id} className="d-flex align-items-center">
            <FaFileAlt size={20} className="text-primary me-2" />
            <a href={file.fileUrl} target="_blank" rel="noopener noreferrer">
              {file.name}
            </a>
          </div>
        ))}
      </div>
    </div>
  );
}
