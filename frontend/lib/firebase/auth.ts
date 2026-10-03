/**
 * Firebase Authentication & Cloud Service Layer for CYBERSPLOI
 * Implements Google Identity Toolkit REST API - light, secure, and zero-dependency,
 * providing Email/Password authentication, Google OAuth, and secure token issuance.
 */

import { firebaseConfig, isFirebaseConfigured } from "./config";

export interface FirebaseAuthUser {
  uid: string;
  email: string;
  displayName?: string;
  idToken: string;
  refreshToken?: string;
  expiresIn?: string;
}

const IDENTITY_TOOLKIT_URL = "https://identitytoolkit.googleapis.com/v1/accounts";

export const firebaseAuth = {
  /**
   * Log in with Email and Password via Firebase
   */
  signInWithEmail: async (email: string, password: string): Promise<FirebaseAuthUser> => {
    if (!firebaseConfig.apiKey) {
      throw new Error("Firebase API Key is not configured. Please add NEXT_PUBLIC_FIREBASE_API_KEY in .env.local.");
    }

    const response = await fetch(`${IDENTITY_TOOLKIT_URL}:signInWithPassword?key=${firebaseConfig.apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        password,
        returnSecureToken: true,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      const errorMsg = data.error?.message || "Failed to log in with Firebase.";
      if (errorMsg === "EMAIL_NOT_FOUND" || errorMsg === "INVALID_PASSWORD") {
        throw new Error("Invalid email or password.");
      } else if (errorMsg === "USER_DISABLED") {
        throw new Error("This account has been disabled.");
      }
      throw new Error(errorMsg);
    }

    return {
      uid: data.localId,
      email: data.email,
      displayName: data.displayName || data.email.split("@")[0],
      idToken: data.idToken,
      refreshToken: data.refreshToken,
      expiresIn: data.expiresIn,
    };
  },

  /**
   * Create a new user account with Email and Password via Firebase
   */
  signUpWithEmail: async (
    email: string,
    password: string,
    displayName?: string
  ): Promise<FirebaseAuthUser> => {
    if (!firebaseConfig.apiKey) {
      throw new Error("Firebase API Key is not configured. Please add NEXT_PUBLIC_FIREBASE_API_KEY in .env.local.");
    }

    const response = await fetch(`${IDENTITY_TOOLKIT_URL}:signUp?key=${firebaseConfig.apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email,
        password,
        returnSecureToken: true,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      const errorMsg = data.error?.message || "Failed to sign up with Firebase.";
      if (errorMsg === "EMAIL_EXISTS") {
        throw new Error("An account with this email address already exists.");
      } else if (errorMsg === "OPERATION_NOT_ALLOWED") {
        throw new Error("Email/password sign-in is not enabled in your Firebase project console.");
      } else if (errorMsg === "WEAK_PASSWORD : Password should be at least 6 characters") {
        throw new Error("Password must be at least 6 characters long.");
      }
      throw new Error(errorMsg);
    }

    // Optionally update display name
    if (displayName && data.idToken) {
      try {
        await fetch(`${IDENTITY_TOOLKIT_URL}:update?key=${firebaseConfig.apiKey}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            idToken: data.idToken,
            displayName,
            returnSecureToken: false,
          }),
        });
      } catch (e) {
        // Non-blocking display name update
      }
    }

    return {
      uid: data.localId,
      email: data.email,
      displayName: displayName || data.email.split("@")[0],
      idToken: data.idToken,
      refreshToken: data.refreshToken,
      expiresIn: data.expiresIn,
    };
  },

  /**
   * Send password reset email via Firebase
   */
  sendPasswordReset: async (email: string): Promise<boolean> => {
    if (!firebaseConfig.apiKey) {
      throw new Error("Firebase API Key is not configured.");
    }

    const response = await fetch(`${IDENTITY_TOOLKIT_URL}:sendOobCode?key=${firebaseConfig.apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        requestType: "PASSWORD_RESET",
        email,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error?.message || "Failed to send password reset email.");
    }
    return true;
  },

  /**
   * Verify token or lookup user profile
   */
  getUserData: async (idToken: string) => {
    if (!firebaseConfig.apiKey) return null;

    const response = await fetch(`${IDENTITY_TOOLKIT_URL}:lookup?key=${firebaseConfig.apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken }),
    });

    if (!response.ok) return null;
    const data = await response.json();
    return data.users?.[0] || null;
  },

  /**
   * Status helper
   */
  isConfigured: isFirebaseConfigured,
};
