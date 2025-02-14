const API_BASE_URL = "http://localhost:8999";

const API_ENDPOINTS = {
  GET_USERS: `${API_BASE_URL}/users/find/all`,
  GET_USERBYID: `${API_BASE_URL}/users/get`,
  CREATE_EMPLOYEE: `${API_BASE_URL}/users/create`,
  FIND_USER: "/find-user",
  MANAGE_USERS: "/manage-users",
  UPDATE_USER: `${API_BASE_URL}/users/edit`, // ✅ Added correct endpoint for updating a user

  GET_MESSAGES: `${API_BASE_URL}/message/getAll`,
  SEND_MESSAGES: `${API_BASE_URL}/message/add`,
  GET_CONTACTS: `${API_BASE_URL}/message/getAllContacts`,
  GET_ID : `${API_BASE_URL}/users/getId`
};

export { API_BASE_URL, API_ENDPOINTS };
