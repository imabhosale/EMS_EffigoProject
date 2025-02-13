const API_BASE_URL = "http://localhost:8999";

const API_ENDPOINTS = {
  GET_USERS: `${API_BASE_URL}/users/find/all`,
  GET_USERBYID: `${API_BASE_URL}/users/get`,
  CREATE_EMPLOYEE: `${API_BASE_URL}/users/create`,
  FIND_USER: "/find-user",
  MANAGE_USERS: "/manage-users",
  UPDATE_USER: `${API_BASE_URL}/users/edit`, // ✅ Added correct endpoint for updating a user

};

export { API_BASE_URL, API_ENDPOINTS };
