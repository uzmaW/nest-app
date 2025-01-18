import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { RequestContext } from '../request-context';

@Injectable()
export class RequestContextMiddleware implements NestMiddleware {
  constructor(private requestContext: RequestContext) {}

  use(req: Request, res: Response, next: NextFunction) {
    // Set basic request metadata
    this.requestContext.requestId = uuidv4();
    this.requestContext.ip = this.getClientIp(req);
    this.requestContext.userAgent = req.get('user-agent') || '';
    this.requestContext.path = req.path;
    this.requestContext.method = req.method;
    this.requestContext.timestamp = new Date();

    // If user is authenticated (assuming JWT payload is set in req.user)
    if (req.user) {
      this.requestContext.userId = (req.user as any).sub;
      this.requestContext.userEmail = (req.user as any).email;
      this.requestContext.userRole = (req.user as any).role;
    }

    next();
  }

  private getClientIp(req: Request): string {
    const forwardedFor = req.get('x-forwarded-for');
    if (forwardedFor) {
      return forwardedFor.split(',')[0].trim();
    }
    return req.ip || '';
  }
}