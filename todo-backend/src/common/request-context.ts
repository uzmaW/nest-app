import { Injectable, Scope } from '@nestjs/common';

@Injectable({ scope: Scope.REQUEST })
export class RequestContext {
  private context: Map<string, any> = new Map();

  // User context
  private _userId: number;
  private _userEmail: string;
  private _userRole: string;

  // Request metadata
  private _requestId: string;
  private _ip: string;
  private _userAgent: string;
  private _path: string;
  private _method: string;
  private _timestamp: Date;

  // Getters and setters for user context
  get userId(): number {
    return this._userId;
  }

  set userId(value: number) {
    this._userId = value;
  }

  get userEmail(): string {
    return this._userEmail;
  }

  set userEmail(value: string) {
    this._userEmail = value;
  }

  get userRole(): string {
    return this._userRole;
  }

  set userRole(value: string) {
    this._userRole = value;
  }

  // Getters and setters for request metadata
  get requestId(): string {
    return this._requestId;
  }

  set requestId(value: string) {
    this._requestId = value;
  }

  get ip(): string {
    return this._ip;
  }

  set ip(value: string) {
    this._ip = value;
  }

  get userAgent(): string {
    return this._userAgent;
  }

  set userAgent(value: string) {
    this._userAgent = value;
  }

  get path(): string {
    return this._path;
  }

  set path(value: string) {
    this._path = value;
  }

  get method(): string {
    return this._method;
  }

  set method(value: string) {
    this._method = value;
  }

  get timestamp(): Date {
    return this._timestamp;
  }

  set timestamp(value: Date) {
    this._timestamp = value;
  }

  // Custom context management
  set(key: string, value: any): void {
    this.context.set(key, value);
  }

  get(key: string): any {
    return this.context.get(key);
  }

  has(key: string): boolean {
    return this.context.has(key);
  }

  delete(key: string): boolean {
    return this.context.delete(key);
  }

  clear(): void {
    this.context.clear();
  }
}