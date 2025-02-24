import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { jwtDecode } from "jwt-decode";
import "bootstrap/dist/css/bootstrap.min.css";
import { X } from "lucide-react"; // Importing the close (X) icon
import axios from "axios";
import forge from "node-forge";
export default function Login({ setIsLoggedIn }) {
  const [formData, setFormData] = useState({ email: "", password: "" });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [publicKey, setPublicKey] = useState();
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleLogin = async () => {
    if (!formData.email || !formData.password) {
      setError("Email and Password are required");
      return;
    }

    setLoading(true);
    setError("");

    try {

      const formDataSending = {...formData, "password":getBase64Encrypted(formData.password, convertToPEM(publicKey))}
      const jsonFormData = JSON.stringify(formDataSending);
      console.log(jsonFormData);

      const response = await fetch("http://localhost:8999/users/authenticate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: jsonFormData,
      });

      if (!response.ok) {
        // If response is not ok (non-2xx status), handle the error
        const errorData = await response.text(); // Get the raw response text
        setError(errorData || "Invalid Email or Password");
        return;
      }

      const data = await response.json();

      alert("Login successful!");
      sessionStorage.setItem("jwtToken", data.token);
      setIsLoggedIn(true);

      // Decode token to extract roles
      const decodedToken = jwtDecode(data.token);
      const userRoles = decodedToken.roles
        ? decodedToken.roles.split(",")
        : [decodedToken.role || "USER"];

      const trimmedRoles = userRoles.map((role) => role.trim());
      console.log("User Roles:", trimmedRoles);

      // Redirect based on roles
      if (trimmedRoles.includes("ROLE_ADMIN")) {
        navigate("/admin-dashboard");
      } else if (trimmedRoles.includes("ROLE_USER")) {
        navigate("/user-dashboard");
      } else {
        setError("⚠️ Invalid role assigned. Contact support.");
      }
    } catch (error) {
      console.error("Login error:", error);
      setError("Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const fetchPublicKey = async () => {
    try {
      const key_response = await axios.get("http://localhost:8999/users/key");

      setPublicKey(key_response.data.key);
    } 
    catch (e){
      console.error(e.message);
    }
  };

  useEffect(()=>{
    fetchPublicKey();
  },[])

  useEffect(() => {
    if(publicKey){
      console.log("Public Key Changed:");
      console.log(publicKey);
      console.log(convertToPEM(publicKey));
      console.log(getBase64Encrypted("Hello", convertToPEM(publicKey)));
    }
  }, [publicKey])

  const getBase64Encrypted = (message, pemKey) => {
    const pk = forge.pki.publicKeyFromPem(pemKey);
    return forge.util.encode64(pk.encrypt(message));
  }
  
  const convertToPEM = (publicKey) =>{
    return "-----BEGIN PUBLIC KEY-----\n" +
                publicKey +
          "\n-----END PUBLIC KEY-----";
  }

  return (
    <div className="container d-flex justify-content-center align-items-center vh-100">
      <div className="card shadow-lg p-4 position-relative" style={{ width: "350px" }}>
        {/* Close (X) Icon */}
        <X
          size={24}
          className="position-absolute top-0 end-0 m-2 text-muted"
          style={{ cursor: "pointer" }}
          onClick={() => navigate("/")}
        />

        <h2 className="text-center mb-3">Login</h2>

        {error && <div className="alert alert-danger">{error}</div>}

        <div className="mb-3">
          <label className="form-label">Email</label>
          <input
            name="email"
            type="email"
            placeholder="Enter your email"
            value={formData.email}
            onChange={handleChange}
            className="form-control"
          />
        </div>

        <div className="mb-3">
          <label className="form-label">Password</label>
          <input
            name="password"
            type="password"
            placeholder="Enter your password"
            value={formData.password}
            onChange={handleChange}
            className="form-control"
          />
        </div>

        <button
          onClick={handleLogin}
          className="btn btn-primary w-100 mb-2"
          disabled={loading}
        >
          {loading ? (
            <>
              <span
                className="spinner-border spinner-border-sm"
                role="status"
                aria-hidden="true"
              ></span>{" "}
              Logging in...
            </>
          ) : (
            "Login"
          )}
        </button>

        {/* Register Link */}
        <p className="text-center mt-2">
          Don't have an account?{" "}
          <span
            className="text-primary"
            style={{ cursor: "pointer" }}
            onClick={() => navigate("/register")}
          >
            Register here
          </span>
        </p>
      </div>
    </div>
  );
}
