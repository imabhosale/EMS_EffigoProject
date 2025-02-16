import React, { useState } from "react";
import "bootstrap/dist/css/bootstrap.min.css";

const Hero = () => {
  const [showModal, setShowModal] = useState(false);

  return (
    <>
      <section className="bg-dark text-white text-center d-flex align-items-center justify-content-center vh-100">
        <div className="container">
          <h1 className="display-4 fw-bold text-warning">Efficient Employee Management</h1>
          <p className="lead text-light">
            Effortlessly manage employees with secure role-based access control.
          </p>
          <div className="mt-4">
            <button className="btn btn-warning btn-lg me-3" onClick={() => setShowModal(true)}>
              Get Started
            </button>
            <button className="btn btn-outline-light btn-lg" onClick={() => setShowModal(true)}>
              Learn More
            </button>
          </div>
        </div>
      </section>

      {/* Bootstrap Modal */}
      {showModal && (
        <div className="modal fade show d-block" tabIndex="-1" style={{ background: "rgba(0,0,0,0.5)" }}>
          <div className="modal-dialog modal-dialog-centered">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">Login Required</h5>
                <button className="btn-close" onClick={() => setShowModal(false)}></button>
              </div>
              <div className="modal-body">
                <p>You are required to log in to see our features. Please log in.</p>
                <p className="mt-2">Don't have an account? <a href="/register" className="text-primary">Register here</a>.</p>
              </div>
              <div className="modal-footer">
                <button className="btn btn-primary" onClick={() => setShowModal(false)}>
                  OK
                </button>
                <a href="/login" className="btn btn-success">Login</a>
                <a href="/register" className="btn btn-outline-primary">Register</a>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};

export default Hero;
