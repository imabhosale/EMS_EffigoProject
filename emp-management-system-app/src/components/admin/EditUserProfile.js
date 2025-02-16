import { useState, useEffect, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import { API_ENDPOINTS } from "../config/Config";
import { FaEdit } from "react-icons/fa";
import MakeAdmin from "./MakeAdmin"; // Importing the MakeAdmin component

export default function EditUserProfile() {
  const { userId } = useParams();
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [editedUser, setEditedUser] = useState({
    firstName: "",
    lastName: "",
    email: "",
    mobile: "",
    status: "",
  });
  const [isEditing, setIsEditing] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [selectedFile, setSelectedFile] = useState("");
  const [showDocuments, setShowDocuments] = useState(false);

  // ✅ Wrap fetchUser in useCallback to avoid infinite re-renders
  const fetchUser = useCallback(async () => {
    try {
      const token = sessionStorage.getItem("jwtToken");

      if (!token) {
        alert("User is not authenticated.");
        return;
      }

      const response = await axios.get(
        `${API_ENDPOINTS.GET_USERBYID}/${encodeURIComponent(userId)}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      let userRoles = [];
      if (Array.isArray(response.data.roles)) {
        userRoles = response.data.roles.map((role) => role.name.trim());
      } else if (typeof response.data.role === "string") {
        userRoles = [response.data.role.trim()];
      }

      setUser(response.data);
      setEditedUser({
        firstName: response.data.firstName || "",
        lastName: response.data.lastName || "",
        email: response.data.email || "",
        mobile: response.data.mobile || "",
        status: response.data.status || "",
      });

      setIsAdmin(userRoles.includes("ADMIN"));
    } catch (error) {
      alert("Failed to fetch user details.");
    }
  }, [userId]); // ✅ Only re-run if userId changes

  // ✅ Call fetchUser inside useEffect after defining it
  useEffect(() => {
    fetchUser();
  }, [fetchUser]); // ✅ Now no warning

  const handleChange = (field, value) => {
    setEditedUser({ ...editedUser, [field]: value });
  };

  const handleSave = async () => {
    if (isAdmin) {
      alert("Admins are not allowed to edit their profile.");
      return;
    }

    const isConfirmed = window.confirm(
      "Are you sure you want to save the changes?"
    );
    if (!isConfirmed) return;

    try {
      const token = sessionStorage.getItem("jwtToken");
      await axios.put(
        `http://localhost:8999/users/edit/${userId}`,
        editedUser,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      alert("User updated successfully!");
      setIsEditing(false);
      navigate("/admin-dashboard");
    } catch (error) {
      alert("Failed to update user.");
    }
  };

  if (!user) return <p className="text-center mt-4">Loading user details...</p>;

  return (
    <div className="container mt-5">
      <div className="d-flex justify-content-between align-items-center">
        <h2 className="text-primary fw-bold">User Profile</h2>
        {!isAdmin && (
          <button
            className="btn btn-outline-primary"
            onClick={() => setIsEditing(!isEditing)}
          >
            <FaEdit size={20} />
          </button>
        )}
      </div>

      <div className="card p-4 shadow-sm">
        <div className="row">
          <div className="col-md-6">
            <div className="mb-3">
              <label className="form-label">User Email</label>
              <input type="text" className="form-control" value={userId} readOnly />
            </div>
            <div className="mb-3">
              <label className="form-label">First Name</label>
              <input
                type="text"
                className="form-control"
                value={editedUser.firstName}
                onChange={(e) => handleChange("firstName", e.target.value)}
                readOnly={!isEditing}
              />
            </div>
            <div className="mb-3">
              <label className="form-label">Last Name</label>
              <input
                type="text"
                className="form-control"
                value={editedUser.lastName}
                onChange={(e) => handleChange("lastName", e.target.value)}
                readOnly={!isEditing}
              />
            </div>
          </div>

          <div className="col-md-6">
            <div className="mb-3">
              <label className="form-label">Email</label>
              <input type="email" className="form-control" value={editedUser.email} readOnly />
            </div>
            <div className="mb-3">
              <label className="form-label">Mobile</label>
              <input
                type="text"
                className="form-control"
                value={editedUser.mobile}
                onChange={(e) => handleChange("mobile", e.target.value)}
                readOnly={!isEditing}
              />
            </div>
            <div className="mb-3">
              <label className="form-label">Status</label>
              <select
                className="form-control"
                value={editedUser.status}
                onChange={(e) => handleChange("status", e.target.value)}
                disabled={!isEditing}
              >
                <option value="ACTIVE">Active</option>
                <option value="INACTIVE">Inactive</option>
                <option value="PENDING">Pending</option>
              </select>
            </div>
          </div>
        </div>

        {!isAdmin && isEditing && (
          <div className="text-center mt-3">
            <button className="btn btn-success me-2" onClick={handleSave}>
              Save Changes
            </button>

            <MakeAdmin userId={userId} />
          </div>
        )}
      </div>

      {showDocuments && user.files && (
        <div className="mt-4">
          <h5>Total Files Uploaded: {user.files.length}</h5>

          {user.files.length > 0 && (
            <div className="mb-3">
              <label className="form-label">Select File to View</label>
              <select
                className="form-control"
                value={selectedFile}
                onChange={(e) => setSelectedFile(e.target.value)}
              >
                <option value="">-- Select a File --</option>
                {user.files.map((file) => (
                  <option key={file.id} value={file.fileUrl}>
                    {file.name}
                  </option>
                ))}
              </select>
            </div>
          )}

          {selectedFile && (
            <div className="text-center mt-3">
              <a
                href={selectedFile}
                target="_blank"
                rel="noopener noreferrer"
                className="btn btn-primary"
              >
                Open Selected File
              </a>
            </div>
          )}
        </div>
      )}

      <div className="text-center mt-4">
        <button
          className="btn btn-info"
          onClick={() => navigate(`/admin-dashboard/upload-documents/${userId}`)}
        >
          Upload Documents
        </button>

        {user.files && user.files.length > 0 && (
          <button
            className="btn btn-warning ms-2"
            onClick={() => setShowDocuments(!showDocuments)}
          >
            {showDocuments ? "Hide Documents" : "View Documents"}
          </button>
        )}
      </div>
    </div>
  );
}
