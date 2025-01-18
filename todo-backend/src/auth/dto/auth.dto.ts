// src/auth/dto/auth.dto.ts
import { IsEmail, IsString, MinLength, MaxLength, 
  IsOptional, IsBoolean, IsNumber, IsDateString, IsEnum, Matches } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class RegisterDto {
  @ApiProperty({ 
    example: 'user@example.com',
    description: 'User email address'
  })
  @IsEmail()
  email: string;

  @ApiProperty({ 
    example: 'Password123!',
    description: 'User password - must contain at least 1 uppercase letter, 1 lowercase letter, and 1 number or special character',
    minLength: 8,
    maxLength: 32
  })
  @IsString()
  @MinLength(8)
  @MaxLength(32)
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Password must contain at least 1 uppercase letter, 1 lowercase letter, and 1 number or special character'
  })
  password: string;

  @ApiProperty({ 
    example: 'John Doe',
    description: 'User full name',
    minLength: 2,
    maxLength: 100
  })
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  name: string;
}

export class LoginDto {
  @ApiProperty({ 
    example: 'user@example.com',
    description: 'User email address'
  })
  @IsEmail()
  email: string;

  @ApiProperty({ 
    description: 'User password'
  })
  @IsString()
  password: string;
}

export class UpdateProfileDto {
  @ApiPropertyOptional({ 
    example: 'user@example.com',
    description: 'New email address'
  })
  @IsOptional()
  @IsEmail()
  email?: string;

  @ApiPropertyOptional({ 
    example: 'John Doe',
    description: 'New user name',
    minLength: 2,
    maxLength: 100
  })
  @IsOptional()
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  name?: string;
}

export class ChangePasswordDto {
  @ApiProperty({ 
    description: 'Current password'
  })
  @IsString()
  currentPassword: string;

  @ApiProperty({ 
    example: 'NewPassword123!',
    description: 'New password - must contain at least 1 uppercase letter, 1 lowercase letter, and 1 number or special character',
    minLength: 8,
    maxLength: 32
  })
  @IsString()
  @MinLength(8)
  @MaxLength(32)
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Password must contain at least 1 uppercase letter, 1 lowercase letter, and 1 number or special character'
  })
  newPassword: string;
}

export class ResetPasswordDto {
  @ApiProperty({ 
    description: 'Password reset token'
  })
  @IsString()
  token: string;

  @ApiProperty({ 
    example: 'NewPassword123!',
    description: 'New password - must contain at least 1 uppercase letter, 1 lowercase letter, and 1 number or special character',
    minLength: 8,
    maxLength: 32
  })
  @IsString()
  @MinLength(8)
  @MaxLength(32)
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Password must contain at least 1 uppercase letter, 1 lowercase letter, and 1 number or special character'
  })
  password: string;
}

export class CreateUserDto {
  @ApiProperty({ 
    example: 'user@example.com',
    description: 'User email address'
  })
  @IsEmail()
  email: string;

  @ApiProperty({ 
    example: 'Password123!',
    description: 'User password - must contain at least 1 uppercase letter, 1 lowercase letter, and 1 number or special character',
    minLength: 8,
    maxLength: 32
  })
  @IsString()
  @MinLength(8)
  @MaxLength(32)
  @Matches(/((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/, {
    message: 'Password must contain at least 1 uppercase letter, 1 lowercase letter, and 1 number or special character'
  })
  password: string;

  @ApiProperty({ 
    example: 'John Doe',
    description: 'User full name',
    minLength: 2,
    maxLength: 100
  })
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  name: string;
}

// Response DTOs
export class TokenResponseDto {
  @ApiProperty({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'JWT access token'
  })
  access_token: string;

  @ApiProperty({
    example: '550e8400-e29b-41d4-a716-446655440000',
    description: 'Refresh token'
  })
  refresh_token: string;

  @ApiProperty({
    example: 3600,
    description: 'Token expiration time in seconds'
  })
  expires_in: number;

  @ApiProperty({
    description: 'User information',
    type: () => ({
      id: Number,
      email: String,
      name: String,
      role: String
    })
  })
  user: {
    id: number;
    email: string;
    name: string;
    role: string;
  };
}

export class RequestPasswordResetDto {
  @ApiProperty({ 
    example: 'user@example.com',
    description: 'Email address for password reset'
  })
  @IsEmail()
  email: string;
}

export class VerifyEmailDto {
  @ApiProperty({ 
    example: '550e8400-e29b-41d4-a716-446655440000',
    description: 'Email verification token'
  })
  @IsString()
  token: string;
}

export class RefreshTokenDto {
  @ApiProperty({ 
    example: '550e8400-e29b-41d4-a716-446655440000',
    description: 'Refresh token'
  })
  @IsString()
  token: string;
}

export class LogoutDto {
  @ApiProperty({ 
    example: '550e8400-e29b-41d4-a716-446655440000',
    description: 'Current refresh token to revoke (optional)',
    required: false
  })
  @IsOptional()
  @IsString()
  refreshToken?: string;

  @ApiProperty({ 
    example: true,
    description: 'Whether to logout from all devices',
    required: false,
    default: false
  })
  @IsOptional()
  @IsBoolean()
  fromAllDevices?: boolean;
}

// Response DTOs
export class UserResponseDto {
  @ApiProperty({ example: 1 })
  id: number;

  @ApiProperty({ example: 'user@example.com' })
  email: string;

  @ApiProperty({ example: 'John Doe' })
  name: string;

  @ApiProperty({ example: 'user', enum: ['admin', 'user'] })
  role: string;

  @ApiProperty({ example: true })
  isEmailVerified: boolean;

  @ApiProperty({ example: '2024-01-18T12:00:00.000Z' })
  createdAt: Date;

  @ApiProperty({ example: '2024-01-18T12:00:00.000Z' })
  updatedAt: Date;
}

export class PaginatedUsersResponseDto {
  @ApiProperty({ 
    type: [UserResponseDto],
    description: 'Array of user objects'
  })
  data: UserResponseDto[];

  @ApiProperty({
    description: 'Pagination metadata',
    type: () => ({
      total: Number,
      page: Number,
      lastPage: Number
    }),
    example: {
      total: 100,
      page: 1,
      lastPage: 10
    }
  })
  meta: {
    total: number;
    page: number;
    lastPage: number;
  };
}

export class AuthEventLogResponseDto {
  @ApiProperty({ example: 1 })
  id: number;

  @ApiProperty({ example: 1 })
  userId: number;

  @ApiProperty({ 
    example: 'LOGIN',
    description: 'Type of authentication event'
  })
  eventType: string;

  @ApiProperty({ 
    example: '192.168.1.1',
    description: 'IP address of the request'
  })
  ipAddress: string;

  @ApiProperty({ 
    example: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...',
    description: 'User agent string from the request'
  })
  userAgent: string;

  @ApiProperty({ example: '2024-01-18T12:00:00.000Z' })
  createdAt: Date;
}
export class PaginationDto {
  @ApiPropertyOptional({
    example: 1,
    description: 'Page number for pagination'
  })
  @IsOptional()
  @IsNumber()
  page?: number;

  @ApiPropertyOptional({
    example: 10,
    description: 'Number of items per page'
  })
  @IsOptional()
  @IsNumber()
  limit?: number;
}
export class AuthEventLogDto {
  @ApiProperty({
    example: 1,
    description: 'User ID'
  })
  @IsNumber()
  userId: number;

  @ApiProperty({
    example: 'LOGIN',
    description: 'Type of authentication event'
  })
  @IsString()
  eventType: string;

  @ApiProperty({
    example: '192.168.1.1',
    description: 'IP address of the request'
  })
  @IsString()
  ipAddress: string;

  @ApiProperty({
    example: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...',
    description: 'User agent string from the request'
  })
  @IsString()
  userAgent: string;
}

export class MessageResponseDto {
  @ApiProperty({ 
    example: 'Operation completed successfully',
    description: 'Response message'
  })
  message: string;
}

export class ErrorResponseDto {
  @ApiProperty({ 
    example: 400,
    description: 'HTTP status code'
  })
  statusCode: number;

  @ApiProperty({ 
    example: ['email must be a valid email address'],
    description: 'Array of error messages'
  })
  message: string[];

  @ApiProperty({ 
    example: 'Bad Request',
    description: 'Error type'
  })
  error: string;
}

// Query DTOs
export class UserFilterDto extends PaginationDto {
  @ApiPropertyOptional({ 
    example: 'john',
    description: 'Search term for user name or email'
  })
  @IsOptional()
  @IsString()
  search?: string;

  @ApiPropertyOptional({ 
    example: 'admin',
    enum: ['admin', 'user'],
    description: 'Filter by user role'
  })
  @IsOptional()
  @IsEnum(['admin', 'user'])
  role?: string;

  @ApiPropertyOptional({ 
    example: true,
    description: 'Filter by email verification status'
  })
  @IsOptional()
  @IsBoolean()
  isEmailVerified?: boolean;
}

export class AuthEventLogFilterDto extends PaginationDto {
  @ApiPropertyOptional({ 
    example: 1,
    description: 'Filter by user ID'
  })
  @IsOptional()
  @IsNumber()
  userId?: number;

  @ApiPropertyOptional({ 
    example: 'LOGIN',
    description: 'Filter by event type'
  })
  @IsOptional()
  @IsString()
  eventType?: string;

  @ApiPropertyOptional({ 
    example: '2024-01-18',
    description: 'Filter by date (YYYY-MM-DD)'
  })
  @IsOptional()
  @IsDateString()
  date?: string;
}
