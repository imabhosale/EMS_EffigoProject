import { useState } from "react";
import { useNavigate } from "react-router-dom"; // Import useNavigate
import axios from "axios";
import { API_ENDPOINTS } from "../config/Config";

export default function MakeAdmin({ userId, onAdminMade }) {
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate(); // Hook for navigation

  const handleMakeAdmin = async () => {
    const isConfirmed = window.confirm("Are you sure you want to make this user an admin?");
    if (!isConfirmed) return;

    try {
      setIsLoading(true);
      const token = sessionStorage.getItem("jwtToken");

      await axios.post(
        `${API_ENDPOINTS.MAKE_ADMIN}/${encodeURIComponent(userId)}/make-admin`, 
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );

      alert("User has been made an admin successfully!");
      
      // Notify parent component
      if (onAdminMade) onAdminMade();

      // Redirect to Admin Dashboard
      navigate("/admin-dashboard/find-all");
      
    } catch (error) {
      console.error("Error making user admin:", error);
      alert("Failed to make the user an admin.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="mt-3 text-center">
      <button className="btn btn-danger" onClick={handleMakeAdmin} disabled={isLoading}>
        {isLoading ? "Processing..." : "Make Admin"}
      </button>
    </div>
  );
}
