import axios from "axios";

const API_BASE_URL = "http://localhost:8999/users";

const ApiService = {
  uploadFile: async (userId, file) => {
    const token = sessionStorage.getItem("jwtToken");

    const formData = new FormData();
    formData.append("file", file);

    return axios.post(`${API_BASE_URL}/uploadFile/${userId}`, formData, {
      headers: {
        "Content-Type": "multipart/form-data",
        Authorization: `Bearer ${token}`,
      },
    });
  },
};

export default ApiService;
