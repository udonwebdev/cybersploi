export interface ApplicationSession {
  sessionId: string;
  engagementId: string;
  role: string;
  userId?: string;
  cookies: Record<string, string>;
  headers: Record<string, string>;
  tokens: Record<string, string>; // e.g. csrfToken, jwt, bearer
  stateVariables: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
  isValid: boolean;
}

export class StatefulSessionService {
  private static activeSessions: Map<string, ApplicationSession> = new Map();

  /**
   * Initialize or update a stateful session for an authorized role
   */
  public static createSession(
    engagementId: string,
    role: string,
    initialContext: {
      userId?: string;
      cookies?: Record<string, string>;
      headers?: Record<string, string>;
      tokens?: Record<string, string>;
    } = {}
  ): ApplicationSession {
    const sessionId = `sess-${engagementId.slice(0, 8)}-${role.toLowerCase()}`;
    const session: ApplicationSession = {
      sessionId,
      engagementId,
      role,
      userId: initialContext.userId,
      cookies: initialContext.cookies || {},
      headers: initialContext.headers || {},
      tokens: initialContext.tokens || {},
      stateVariables: {},
      createdAt: new Date(),
      updatedAt: new Date(),
      isValid: true
    };

    this.activeSessions.set(sessionId, session);
    return session;
  }

  public static getSession(sessionId: string): ApplicationSession | undefined {
    return this.activeSessions.get(sessionId);
  }

  public static updateCookies(sessionId: string, newCookies: Record<string, string>) {
    const session = this.activeSessions.get(sessionId);
    if (session) {
      session.cookies = { ...session.cookies, ...newCookies };
      session.updatedAt = new Date();
    }
  }

  public static updateTokens(sessionId: string, newTokens: Record<string, string>) {
    const session = this.activeSessions.get(sessionId);
    if (session) {
      session.tokens = { ...session.tokens, ...newTokens };
      session.updatedAt = new Date();
    }
  }

  public static invalidateSession(sessionId: string) {
    const session = this.activeSessions.get(sessionId);
    if (session) {
      session.isValid = false;
      session.updatedAt = new Date();
    }
  }
}
