import { useState, useEffect, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import axios from "axios";
import { API_ENDPOINTS } from "../config/Config";

export default function EditUserProfileOwn() {
  const { id } = useParams(); // ✅ Get User ID from URL
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [editedUser, setEditedUser] = useState({
    firstName: "",
    lastName: "",
    email: "",
    mobile: "",
  });
  const [isEditing, setIsEditing] = useState(false);
  const [isAdmin, setIsAdmin] = useState(false);
  const [showDocuments, setShowDocuments] = useState(false);
  const [selectedFile, setSelectedFile] = useState("");

  const fetchUser = useCallback(async () => {
    try {
      console.log(`Fetching user details for ID: ${id}`);
      const token = sessionStorage.getItem("jwtToken");

      if (!token) {
        alert("User is not authenticated.");
        navigate("/login");
        return;
      }

      const response = await axios.get(`${API_ENDPOINTS.GET_USERBYID}/${id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      console.log("User data received:", response.data);

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
      });

      // Prevent admins from editing profile
      setIsAdmin(userRoles.includes("ADMIN"));
    } catch (error) {
      console.error("Error fetching user details:", error);
      alert("Failed to fetch user details.");
    }
  }, [id, navigate]);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  const handleChange = (field, value) => {
    setEditedUser({ ...editedUser, [field]: value });
  };

  const handleSave = async () => {
    if (isAdmin) {
      alert("Admins are not allowed to edit their profile.");
      return;
    }

    const isConfirmed = window.confirm("Are you sure you want to save the changes?");
    if (!isConfirmed) return;

    try {
      const token = sessionStorage.getItem("jwtToken");
      await axios.put(`${API_ENDPOINTS.UPDATE_USER}/${id}`, editedUser, {
        headers: { Authorization: `Bearer ${token}` },
      });

      alert("User updated successfully!");
      navigate(`/user-dashboard/profile/${encodeURIComponent(editedUser.email)}`);
    } catch (error) {
      console.error("Error updating user:", error);
      alert("Failed to update user.");
    }
  };

  if (!user) return <p className="text-center mt-4">Loading user details...</p>;

  return (
    <div className="container mt-5">
      <h2 className="text-center text-primary fw-bold">Edit User Profile</h2>
      <div className="card p-4 shadow-sm">
        <div className="row">
          <div className="col-md-6">
            <div className="mb-3">
              <label className="form-label">User ID</label>
              <input type="text" className="form-control" value={id} readOnly />
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
              <input type="text" className="form-control" value={user.status} readOnly />
            </div>
          </div>
        </div>

        {/* ✅ Edit Button */}
        {!isAdmin && (
          <div className="text-center mt-3">
            {!isEditing ? (
              <button className="btn btn-primary" onClick={() => setIsEditing(true)}>
                Edit Profile
              </button>
            ) : (
              <button className="btn btn-success" onClick={handleSave}>
                Save Changes
              </button>
            )}
          </div>
        )}

        {/* ✅ Document Viewing Section */}
        {user.files && user.files.length > 0 && (
          <div className="text-center mt-4">
            <button className="btn btn-warning" onClick={() => setShowDocuments(!showDocuments)}>
              {showDocuments ? "Hide Documents" : "View Documents"}
            </button>
          </div>
        )}

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
      </div>
    </div>
  );
}
