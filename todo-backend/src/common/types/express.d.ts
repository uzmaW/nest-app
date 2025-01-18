import { Request } from 'express';

declare global {
  namespace Express {
    interface Request {
      user?: {
        sub: number;
        email: string;
        role: string;
        [key: string]: any;
      };
    }
  }
}