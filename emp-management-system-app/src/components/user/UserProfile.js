import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";

export default function UserProfile() {
  const { email } = useParams(); // Get encoded email from URL
  const decodedEmail = decodeURIComponent(email); // ✅ Decode it before use
  const navigate = useNavigate(); // ✅ For navigation

  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!decodedEmail || decodedEmail === "undefined") {
      console.error("Invalid user email");
      return;
    }

    setLoading(true);

    fetch(`http://localhost:8999/users/find/${encodeURIComponent(decodedEmail)}`, {
      headers: {
        Authorization: `Bearer ${sessionStorage.getItem("jwtToken")}`, // ✅ Pass JWT Token
      }
    })
      .then((res) => {
        if (res.status === 401) {
          throw new Error("Unauthorized access - Invalid token or expired session.");
        }
        if (!res.ok) {
          throw new Error("User not found");
        }
        return res.json();
      })
      .then((data) => {
        setUser(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Error fetching user:", err);
        setLoading(false);
      });
  }, [decodedEmail]);

  if (loading) {
    return <h2 className="text-center mt-5">Loading user details...</h2>;
  }

  if (!user) {
    return <h2 className="text-center mt-5">No user data found</h2>;
  }

  return (
    <div className="container mt-4">
      <div className="card p-4 shadow">
        <h2 className="text-center">User Profile</h2>
        <p><strong>User ID:</strong> {user.id}</p> {/* ✅ Displaying User ID */}
        <p><strong>First Name:</strong> {user.firstName}</p>
        <p><strong>Last Name:</strong> {user.lastName}</p>
        <p><strong>Email:</strong> {user.email}</p>
        <p><strong>Mobile:</strong> {user.mobile}</p>
        <p><strong>Status:</strong> {user.status}</p>
        <p><strong>Roles:</strong> {user.roles?.map(role => role.name).join(", ")}</p>

        {/* ✅ Edit Button to Navigate to Edit Page */}
        <div className="text-center mt-3">
          <button
            className="btn btn-primary"
            onClick={() => navigate(`/user-dashboard/edit/${user.id}`)} // ✅ Passing ID in URL
          >
            Edit Profile
          </button>
        </div>
      </div>
    </div>
  );
}
