import axios from "axios";

export const apiClient = axios.create({
  baseURL: "/api",
  headers: {
    "Content-Type": "application/json",
  },
  timeout: 30000,
});

// Request interceptor: Attach JWT token from localStorage if available
apiClient.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("cybersploi_token");
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

// Response interceptor: Handle 401 Unauthorized
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (typeof window !== "undefined" && error.response?.status === 401) {
      // Avoid redirect loops on auth routes
      if (!window.location.pathname.startsWith("/login") && !window.location.pathname.startsWith("/register")) {
        localStorage.removeItem("cybersploi_token");
      }
    }
    return Promise.reject(error);
  }
);
