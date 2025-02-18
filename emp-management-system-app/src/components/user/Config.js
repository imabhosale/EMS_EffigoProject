const API_BASE_URL = "http://localhost:8081";

const API_ENDPOINTS = {
  GET_USERS: `${API_BASE_URL}/users/find/all`,
  CREATE_EMPLOYEE: "/create-employee",
  FIND_USER: "/find-user",
  MANAGE_USERS: "/manage-users",
};

export { API_BASE_URL, API_ENDPOINTS };
