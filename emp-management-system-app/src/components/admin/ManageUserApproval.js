import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { API_ENDPOINTS } from "../config/Config";
import { Button, Modal } from "react-bootstrap";

export default function ManageUserApproval() {
  const [users, setUsers] = useState([]);
  const [filteredUsers, setFilteredUsers] = useState([]);
  const [selectedStatus, setSelectedStatus] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);
  const [newStatus, setNewStatus] = useState(""); // NEW STATE FOR STATUS SELECTION
  const navigate = useNavigate();

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const token = sessionStorage.getItem("jwtToken");
      const response = await axios.get(API_ENDPOINTS.GET_USERS, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setUsers(response.data);
      setFilteredUsers(response.data);
    } catch (error) {
      console.error("Error fetching users", error);
    }
  };

  const filterUsers = () => {
    let filtered = users;
    if (selectedStatus !== "ALL") {
      filtered = filtered.filter((user) => user.status === selectedStatus);
    }
    if (searchQuery.trim()) {
      filtered = filtered.filter(
        (user) =>
          user.firstName.toLowerCase().includes(searchQuery.toLowerCase()) ||
          user.lastName.toLowerCase().includes(searchQuery.toLowerCase())
      );
    }
    setFilteredUsers(filtered);
  };

  useEffect(() => {
    filterUsers();
  }, [searchQuery, selectedStatus]);

  const handleStatusChange = (user) => {
    setSelectedUser(user);
    setNewStatus(user.status); // DEFAULT STATUS TO CURRENT STATUS
    setShowModal(true);
  };

  const confirmStatusChange = async () => {
    if (!selectedUser || !newStatus) return;
    try {
      const token = sessionStorage.getItem("jwtToken");
      await axios.put(
        `${API_ENDPOINTS.UPDATE_USER}/${selectedUser.id}`,
        { status: newStatus }, // UPDATED STATUS FROM SELECTED VALUE
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );
      fetchUsers();
      setShowModal(false);
    } catch (error) {
      console.error("Error updating user status", error);
    }
  };

  return (
    <div className="container mt-5">
      <h2 className="text-center text-primary fw-bold mb-4">Manage User Approvals</h2>

      <div className="row mb-3">
        <div className="col-md-4">
          <input
            type="text"
            className="form-control"
            placeholder="Search by First or Last Name"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
        <div className="col-md-3">
          <select
            className="form-select"
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
          >
            <option value="ALL">All Users</option>
            <option value="ACTIVE">Active Users</option>
            <option value="INACTIVE">Inactive Users</option>
            <option value="PENDING">Pending Users</option>
          </select>
        </div>
      </div>

      <div className="table-responsive">
        <table className="table table-bordered table-striped text-center">
          <thead className="table-dark">
            <tr>
              <th>First Name</th>
              <th>Last Name</th>
              <th>Email</th>
              <th>Mobile</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredUsers.length > 0 ? (
              filteredUsers.map((user) => (
                <tr key={user.id}>
                  <td>{user.firstName}</td>
                  <td>{user.lastName}</td>
                  <td>{user.email}</td>
                  <td>{user.mobile}</td>
                  <td>
                    <span
                      className={`badge ${
                        user.status === "ACTIVE"
                          ? "bg-success"
                          : user.status === "INACTIVE"
                          ? "bg-danger"
                          : "bg-warning"
                      }`}
                    >
                      {user.status}
                    </span>
                  </td>
                  <td>
                    <Button
                      variant="primary"
                      onClick={() => handleStatusChange(user)}
                    >
                      Change Status
                    </Button>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="6" className="text-center text-muted">
                  No users found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Confirmation Modal with Status Selection */}
      <Modal show={showModal} onHide={() => setShowModal(false)}>
        <Modal.Header closeButton>
          <Modal.Title>Confirm Status Change</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p>
            Are you sure you want to change the status of{" "}
            <strong>
              {selectedUser?.firstName} {selectedUser?.lastName}
            </strong>
            ?
          </p>
          <select
            className="form-select"
            value={newStatus}
            onChange={(e) => setNewStatus(e.target.value)}
          >
            <option value="ACTIVE">Active</option>
            <option value="INACTIVE">Inactive</option>
            <option value="PENDING">Pending</option>
          </select>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowModal(false)}>
            Cancel
          </Button>
          <Button variant="danger" onClick={confirmStatusChange}>
            Confirm
          </Button>
        </Modal.Footer>
      </Modal>
    </div>
  );
}
