import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { jwtDecode } from "jwt-decode";

export default function useAuth(requiredRole) {
  const navigate = useNavigate();

  useEffect(() => {
    const token = sessionStorage.getItem("jwtToken");

    if (!token) {
      console.log("No token found. Redirecting to login.");
      navigate("/login");
      return;
    }

    try {
      const decodedToken = jwtDecode(token);
      const userRoles = decodedToken.roles
        ? decodedToken.roles.split(",")
        : [decodedToken.role || "USER"];

      const trimmedRoles = userRoles.map((role) => role.trim());
      console.log("User Roles:", trimmedRoles);

      if (!trimmedRoles.includes(requiredRole)) {
        console.error(" comming Unauthorized access. Redirecting to login.");
        navigate("/login");
      }
    } catch (error) {
      console.error("Invalid token. Redirecting to login.");
      navigate("/login");
    }
  }, [navigate, requiredRole]);
}
