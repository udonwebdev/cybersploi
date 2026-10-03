import * as jwt from 'jsonwebtoken';

export interface JwtPayload {
  sub: string;
  email: string;
  orgId?: string;
}

export class JwtService {
  constructor(private secret: string) {}

  generateToken(payload: JwtPayload, expiresIn = '15m'): string {
    return jwt.sign(payload, this.secret, { expiresIn });
  }

  verifyToken(token: string): JwtPayload {
    return jwt.verify(token, this.secret) as JwtPayload;
  }

  generateRefreshToken(payload: JwtPayload): string {
    return jwt.sign(payload, this.secret, { expiresIn: '7d' });
  }
}
