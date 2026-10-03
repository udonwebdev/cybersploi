import { apiClient } from "./client";
import { User } from "../store/auth-store";
import axios from "axios";

export interface LoginResponse {
  token: string;
  user: User;
}

const BACKEND_DIRECT_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export const authApi = {
  login: async (credentials: { email: string; password: string }): Promise<LoginResponse> => {
    try {
      // Primary attempt via Next.js reverse proxy (/api/v1/auth/login)
      const res = await apiClient.post("/v1/auth/login", credentials);
      const token =
        res.data?.token ||
        res.data?.accessToken ||
        res.data?.data?.accessToken ||
        res.data?.data?.token;
      const user = res.data?.user || res.data?.data?.user;
      return { token, user };
    } catch (primaryErr: any) {
      // If Next.js proxy returns 500 or ECONNREFUSED, attempt direct backend fallback
      if (
        primaryErr.response?.status === 500 ||
        primaryErr.code === "ECONNREFUSED" ||
        !primaryErr.response
      ) {
        try {
          const directRes = await axios.post(`${BACKEND_DIRECT_URL}/api/v1/auth/login`, credentials, {
            headers: { "Content-Type": "application/json" },
            timeout: 10000,
          });
          const token =
            directRes.data?.token ||
            directRes.data?.accessToken ||
            directRes.data?.data?.accessToken ||
            directRes.data?.data?.token;
          const user = directRes.data?.user || directRes.data?.data?.user;
          return { token, user };
        } catch (directErr: any) {
          // If direct call fails with 401 or specific message, bubble that up cleanly
          if (directErr.response?.status === 401 || directErr.response?.status === 400) {
            throw directErr;
          }
          throw new Error("Unable to connect to authentication server. Please check your backend connection.");
        }
      }
      throw primaryErr;
    }
  },

  register: async (payload: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    organizationName?: string;
  }): Promise<LoginResponse> => {
    const registerBody = {
      ...payload,
      username: payload.email.split("@")[0],
    };

    try {
      const res = await apiClient.post("/v1/auth/register", registerBody);
      const token =
        res.data?.token ||
        res.data?.accessToken ||
        res.data?.data?.accessToken ||
        res.data?.data?.token;
      const user = res.data?.user || res.data?.data?.user;
      return { token, user };
    } catch (primaryErr: any) {
      if (
        primaryErr.response?.status === 500 ||
        primaryErr.code === "ECONNREFUSED" ||
        !primaryErr.response
      ) {
        try {
          const directRes = await axios.post(`${BACKEND_DIRECT_URL}/api/v1/auth/register`, registerBody, {
            headers: { "Content-Type": "application/json" },
            timeout: 10000,
          });
          const token =
            directRes.data?.token ||
            directRes.data?.accessToken ||
            directRes.data?.data?.accessToken ||
            directRes.data?.data?.token;
          const user = directRes.data?.user || directRes.data?.data?.user;
          return { token, user };
        } catch (directErr: any) {
          if (directErr.response?.status === 400 || directErr.response?.status === 409) {
            throw directErr;
          }
          throw new Error("Unable to connect to registration server. Please check your backend connection.");
        }
      }
      throw primaryErr;
    }
  },

  getMe: async (): Promise<User> => {
    try {
      const res = await apiClient.get("/v1/users/me");
      const u = res.data?.data || res.data;
      const orgData = u.organizations?.[0];
      return {
        id: u.id,
        email: u.email,
        firstName: u.firstName,
        lastName: u.lastName,
        role: orgData?.role || u.role || "Security Analyst",
        organizationId: orgData?.organizationId,
        organizationName: orgData?.organization?.name || "CYBERSPLOI Defense Mesh",
        organization: orgData?.organization?.name || "CYBERSPLOI Defense Mesh",
      };
    } catch (err) {
      // Direct fallback
      const token = typeof window !== "undefined" ? localStorage.getItem("cybersploi_token") : null;
      if (token) {
        const directRes = await axios.get(`${BACKEND_DIRECT_URL}/api/v1/users/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const u = directRes.data?.data || directRes.data;
        const orgData = u.organizations?.[0];
        return {
          id: u.id,
          email: u.email,
          firstName: u.firstName,
          lastName: u.lastName,
          role: orgData?.role || u.role || "Security Analyst",
          organizationId: orgData?.organizationId,
          organizationName: orgData?.organization?.name || "CYBERSPLOI Defense Mesh",
          organization: orgData?.organization?.name || "CYBERSPLOI Defense Mesh",
        };
      }
      throw err;
    }
  },
};
