// src/auth/auth.service.ts
import { 
  Injectable, 
  UnauthorizedException, 
  ConflictException,
  NotFoundException,
  BadRequestException,
  ForbiddenException
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DataSource, LessThan, Not, In, EntityManager, MoreThan } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { MailerService } from '@nestjs-modules/mailer';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';

import { User } from './entities/auth.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { TokenBlacklist } from './entities/token-blacklist.entity';
import { VerificationToken } from './entities/verification-token.entity';
import { AuthEventLog } from './entities/auth-event-log.entity';
import { 
  RegisterDto, 
  LoginDto, 
  UpdateProfileDto, 
  ChangePasswordDto,
  ResetPasswordDto,
  CreateUserDto,
  PaginationDto
} from './dto/auth.dto';
import { RequestContext } from '../common/request-context';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(TokenBlacklist)
    private tokenBlacklistRepository: Repository<TokenBlacklist>,
    @InjectRepository(VerificationToken)
    private verificationTokenRepository: Repository<VerificationToken>,
    @InjectRepository(AuthEventLog)
    private authEventLogRepository: Repository<AuthEventLog>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private mailerService: MailerService,
    private dataSource: DataSource,
    private requestContext: RequestContext
  ) {}

  // User Registration
  async register(registerDto: RegisterDto) {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Check if user exists
      const existingUser = await queryRunner.manager.findOne(User, {
        where: { email: registerDto.email.toLowerCase() }
      });

      if (existingUser) {
        throw new ConflictException('User with this email already exists');
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(registerDto.password, 12);

      // Create user
      const user = queryRunner.manager.create(User, {
        email: registerDto.email.toLowerCase(),
        password: hashedPassword,
        name: registerDto.name,
        role: 'user'
      });

      const savedUser = await queryRunner.manager.save(user);

      // Generate verification token
      const verificationToken = await this.generateVerificationToken(
        savedUser.id,
        'email_verification',
        queryRunner.manager
      );

      // Log event
      await this.logAuthEvent(
        savedUser.id,
        'REGISTER',
        queryRunner.manager
      );

      // Send verification email
      await this.sendVerificationEmail(savedUser, verificationToken.token);

      await queryRunner.commitTransaction();

      const { password, ...result } = savedUser;
      return result;

    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  // User Login
  async login(loginDto: LoginDto) {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const user = await queryRunner.manager.findOne(User, {
        where: { email: loginDto.email.toLowerCase() }
      });

      // Check account lock
      if (user?.lockUntil && user.lockUntil > new Date()) {
        throw new UnauthorizedException('Account is temporarily locked. Please try again later.');
      }

      // Validate password
      if (!user || !(await bcrypt.compare(loginDto.password, user.password))) {
        if (user) {
          await this.handleFailedLogin(user);//, queryRunner.manager);
        }
        throw new UnauthorizedException('Invalid credentials');
      }

      // Check email verification
      if (!user.isEmailVerified) {
        throw new UnauthorizedException('Please verify your email before logging in');
      }

      // Reset login attempts
      if (user.loginAttempts > 0) {
        await queryRunner.manager.update(User, user.id, {
          loginAttempts: 0,
          lastLoginAttempt: null,
          lockUntil: null
        });
      }

      // Generate tokens
      const accessToken = this.generateAccessToken(user);
      const refreshToken = await this.generateRefreshToken(
        user.id,
        queryRunner.manager
      );

      // Log event
      await this.logAuthEvent(
        user.id,
        'LOGIN',
        queryRunner.manager
      );

      await queryRunner.commitTransaction();

      return {
        access_token: accessToken,
        refresh_token: refreshToken.token,
        expires_in: this.configService.get('jwt.expiresIn'),
        user: { id: user.id, email: user.email, name: user.name, role: user.role }
      };

    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }
  
  // validate
  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.userRepository.findOne({ 
      where: { email: email.toLowerCase() } 
    });

    // Check if account is locked
    if (user?.lockUntil && user.lockUntil > new Date()) {
      throw new UnauthorizedException('Account is temporarily locked. Please try again later.');
    }

    if (user) {
      // Update login attempts
      const isPasswordValid = await bcrypt.compare(password, user.password);
      
      if (!isPasswordValid) {
        await this.handleFailedLogin(user);
        throw new UnauthorizedException('Invalid credentials');
      }

      // Reset login attempts on successful login
      if (user.loginAttempts > 0) {
        await this.userRepository.update(user.id, {
          loginAttempts: 0,
          lastLoginAttempt: null,
          lockUntil: null
        });
      }

      const { password: _, ...result } = user;
      return result;
    }
    return null;
  }

  async validateToken(token: string): Promise<boolean> {
    const blacklistedToken = await this.tokenBlacklistRepository.findOne({
      where: { token }
    });

    return !blacklistedToken;
  }

  // Logout
  async logout(accessToken: string, refreshToken?: string, userId?: number) {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const decodedToken = this.jwtService.decode(accessToken) as { exp: number; sub: number };

      // Blacklist access token
      await queryRunner.manager.save(TokenBlacklist, {
        token: accessToken,
        expiresAt: new Date(decodedToken.exp * 1000),
        userId: decodedToken.sub
      });

      // Revoke specific refresh token
      if (refreshToken) {
        await queryRunner.manager.update(RefreshToken,
          { token: refreshToken },
          { isRevoked: true }
        );
      }

      // Revoke all user's refresh tokens
      if (userId) {
        await queryRunner.manager.update(RefreshToken,
          { userId, isRevoked: false },
          { isRevoked: true }
        );
      }

      // Log event
      await this.logAuthEvent(
        decodedToken.sub,
        'LOGOUT',
        queryRunner.manager
      );

      await queryRunner.commitTransaction();

    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  async logoutAllSessions(userId: number): Promise<void> {
    try {
      await this.dataSource.transaction(async (transactionalEntityManager) => {
        // 1. Revoke all refresh tokens
        await transactionalEntityManager.update(RefreshToken,
          { userId, isRevoked: false },
          { isRevoked: true }
        );

        // 2. Blacklist all valid access tokens
        const activeTokens = await transactionalEntityManager.find(RefreshToken, {
          where: { userId, isRevoked: false }
        });

        // Create blacklist entries for each token
        const blacklistPromises = activeTokens.map(token => 
          transactionalEntityManager.save(TokenBlacklist, {
            token: token.token,
            expiresAt: token.expiresAt,
            userId
          })
        );

        await Promise.all(blacklistPromises);

        // 3. Log the mass logout event
        await transactionalEntityManager.save(AuthEventLog, {
          userId,
          type: 'LOGOUT_ALL_SESSIONS',
          ipAddress: this.requestContext.get('ip'),
          userAgent: this.requestContext.get('user-agent')
        });
      });
    } catch (error) {
      console.error('Mass logout operation failed:', error);
      throw new UnauthorizedException('Failed to logout all sessions. Please try again.');
    }
  }

  // Get User Profile
  async getProfile(userId: number) {
    const user = await this.userRepository.findOne({
      where: { id: userId }
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const { password, ...result } = user;
    return result;
  }

  // Update User Profile
  async updateProfile(userId: number, updateDto: UpdateProfileDto) {
    const user = await this.userRepository.findOne({
      where: { id: userId }
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check email uniqueness if email is being updated
    if (updateDto.email && updateDto.email !== user.email) {
      const existingUser = await this.userRepository.findOne({
        where: { email: updateDto.email.toLowerCase() }
      });

      if (existingUser) {
        throw new ConflictException('Email already in use');
      }

      user.isEmailVerified = false;
    }

    // Update user
    Object.assign(user, {
      ...updateDto,
      email: updateDto.email?.toLowerCase()
    });

    const savedUser = await this.userRepository.save(user);
    const { password, ...result } = savedUser;

    // Send verification email if email changed
    if (updateDto.email && updateDto.email !== user.email) {
      const verificationToken = await this.generateVerificationToken(user.id, 'email_verification');
      await this.sendVerificationEmail(user, verificationToken.token);
    }

    return result;
  }

  // Change Password
  async changePassword(userId: number, changePasswordDto: ChangePasswordDto) {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const user = await queryRunner.manager.findOne(User, {
        where: { id: userId }
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      // Verify current password
      const isPasswordValid = await bcrypt.compare(
        changePasswordDto.currentPassword,
        user.password
      );

      if (!isPasswordValid) {
        throw new UnauthorizedException('Current password is incorrect');
      }

      // Update password
      const hashedPassword = await bcrypt.hash(changePasswordDto.newPassword, 12);
      user.password = hashedPassword;

      await queryRunner.manager.save(user);

      // Revoke all refresh tokens
      await queryRunner.manager.update(RefreshToken,
        { userId, isRevoked: false },
        { isRevoked: true }
      );

      // Log event
      await this.logAuthEvent(
        userId,
        'PASSWORD_CHANGE',
        queryRunner.manager
      );

      await queryRunner.commitTransaction();

    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  // Request Password Reset
  async requestPasswordReset(email: string) {
    const user = await this.userRepository.findOne({
      where: { email: email.toLowerCase() }
    });

    if (!user) {
      // Don't reveal user existence
      return;
    }

    const resetToken = await this.generateVerificationToken(
      user.id,
      'password_reset',
      undefined,
      2 // 2 hours expiry
    );

    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Password Reset Request',
      template: 'password-reset',
      context: {
        name: user.name,
        resetUrl: `${this.configService.get('APP_URL')}/auth/reset-password?token=${resetToken.token}`
      }
    });

    await this.logAuthEvent(user.id, 'PASSWORD_RESET_REQUEST');
  }

  // Reset Password
  async resetPassword(resetDto: ResetPasswordDto) {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const resetToken = await queryRunner.manager.findOne(VerificationToken, {
        where: { 
          token: resetDto.token,
          type: 'password_reset'
        }
      });

      if (!resetToken || resetToken.expiresAt < new Date()) {
        throw new BadRequestException('Invalid or expired reset token');
      }

      // Update password
      const hashedPassword = await bcrypt.hash(resetDto.password, 12);
      await queryRunner.manager.update(User, resetToken.userId, {
        password: hashedPassword
      });

      // Revoke all refresh tokens
      await queryRunner.manager.update(RefreshToken,
        { userId: resetToken.userId, isRevoked: false },
        { isRevoked: true }
      );

      // Remove used token
      await queryRunner.manager.remove(resetToken);

      // Log event
      await this.logAuthEvent(
        resetToken.userId,
        'PASSWORD_RESET',
        queryRunner.manager
      );

      await queryRunner.commitTransaction();

    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  // Delete User
  async deleteUser(userId: number, currentUserId: number) {
    const user = await this.userRepository.findOne({
      where: { id: userId }
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Prevent self-deletion for last admin
    if (user.role === 'admin') {
      const adminCount = await this.userRepository.count({
        where: { role: 'admin' }
      });

      if (adminCount === 1 && userId === currentUserId) {
        throw new ForbiddenException('Cannot delete the last admin user');
      }
    }

    await this.userRepository.remove(user);
    await this.logAuthEvent(currentUserId, 'USER_DELETE');
  }

  // Get All Users (with pagination)
  async getAllUsers(paginationDto: PaginationDto) {
    const [users, total] = await this.userRepository.findAndCount({
      skip: (paginationDto.page - 1) * paginationDto.limit,
      take: paginationDto.limit,
      order: { createdAt: 'DESC' }
    });

    const sanitizedUsers = users.map(user => {
      const { password, ...result } = user;
      return result;
    });

    return {
      data: sanitizedUsers,
      meta: {
        total,
        page: paginationDto.page,
        lastPage: Math.ceil(total / paginationDto.limit)
      }
    };
  }

  // Helper Methods
  private async generateVerificationToken(
    userId: number,
    type: 'email_verification' | 'password_reset',
    manager?: EntityManager,
    expiresInHours: number = 24
  ): Promise<VerificationToken> {
    const token = crypto.randomBytes(32).toString('hex');
    const verificationToken = this.verificationTokenRepository.create({
      token,
      userId,
      type,
      expiresAt: new Date(Date.now() + expiresInHours * 60 * 60 * 1000)
    });

    return this.verificationTokenRepository.save(verificationToken);
  }

  private generateAccessToken(user: User): string {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role
    };

    return this.jwtService.sign(payload);
  }

  private async generateRefreshToken(
    userId: number,
    manager?: EntityManager
  ): Promise<RefreshToken> {
    const token = uuidv4();
    const expiresIn = this.configService.get('jwt.refreshExpiresIn', 60 * 60 * 24 * 30);

    const refreshToken = this.refreshTokenRepository.create({
      token,
      userId,
      expiresAt: new Date(Date.now() + expiresIn * 1000)
    });

    return this.refreshTokenRepository.save(refreshToken);
  }

  private async handleFailedLogin(user: User) {
    const maxAttempts = this.configService.get('auth.maxLoginAttempts', 5);
    const lockTime = this.configService.get('auth.lockTime', 15); // Lock time in minutes
    
    // Update login attempts
    const loginAttempts = (user.loginAttempts || 0) + 1;
    const updates: Partial<User> = {
      loginAttempts,
      lastLoginAttempt: new Date()
    };

    // Lock account if max attempts exceeded
    if (loginAttempts >= maxAttempts) {
      updates.lockUntil = new Date(Date.now() + lockTime * 60 * 1000);
    }

    await this.userRepository.update(user.id, updates);
  }

  // Verify Email
  async verifyEmail(token: string) {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const verificationToken = await queryRunner.manager.findOne(VerificationToken, {
        where: { 
          token,
          type: 'email_verification'
        }
      });

      if (!verificationToken || verificationToken.expiresAt < new Date()) {
        throw new BadRequestException('Invalid or expired verification token');
      }

      // Update user verification status
      await queryRunner.manager.update(User, verificationToken.userId, {
        isEmailVerified: true
      });

      // Remove used token
      await queryRunner.manager.remove(verificationToken);

      // Log event
      await this.logAuthEvent(
        verificationToken.userId,
        'EMAIL_VERIFIED',
        queryRunner.manager
      );

      await queryRunner.commitTransaction();

    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  // Refresh Access Token
  async refreshToken(refreshToken: string) {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      const token = await queryRunner.manager.findOne(RefreshToken, {
        where: { 
          token: refreshToken,
          isRevoked: false,
          expiresAt: MoreThan(new Date())
        },
        relations: ['user']
      });

      if (!token) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      // Revoke current refresh token
      await queryRunner.manager.update(RefreshToken, token.id, {
        isRevoked: true
      });

      // Generate new tokens
      const accessToken = this.generateAccessToken(token.user);
      const newRefreshToken = await this.generateRefreshToken(
        token.user.id,
        queryRunner.manager
      );

      // Log event
      await this.logAuthEvent(
        token.user.id,
        'TOKEN_REFRESH',
        queryRunner.manager
      );

      await queryRunner.commitTransaction();

      return {
        access_token: accessToken,
        refresh_token: newRefreshToken.token,
        expires_in: this.configService.get('jwt.expiresIn')
      };

    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  // Create Admin User
  async createAdminUser(createUserDto: CreateUserDto) {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Check if user exists
      const existingUser = await queryRunner.manager.findOne(User, {
        where: { email: createUserDto.email.toLowerCase() }
      });

      if (existingUser) {
        throw new ConflictException('User with this email already exists');
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(createUserDto.password, 12);

      // Create user
      const user = queryRunner.manager.create(User, {
        email: createUserDto.email.toLowerCase(),
        password: hashedPassword,
        name: createUserDto.name,
        role: 'admin',
        isEmailVerified: true // Admin users are pre-verified
      });

      const savedUser = await queryRunner.manager.save(user);

      // Log event
      await this.logAuthEvent(
        this.requestContext.userId,
        'ADMIN_USER_CREATE',
        queryRunner.manager
      );

      await queryRunner.commitTransaction();

      const { password, ...result } = savedUser;
      return result;

    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  // Clean up expired tokens
  async cleanupExpiredTokens() {
    const queryRunner = this.dataSource.createQueryRunner();
    await queryRunner.connect();
    await queryRunner.startTransaction();

    try {
      // Clean up expired verification tokens
      await queryRunner.manager.delete(VerificationToken, {
        expiresAt: LessThan(new Date())
      });

      // Clean up expired refresh tokens
      await queryRunner.manager.delete(RefreshToken, {
        expiresAt: LessThan(new Date())
      });

      // Clean up expired blacklisted tokens
      await queryRunner.manager.delete(TokenBlacklist, {
        expiresAt: LessThan(new Date())
      });

      await queryRunner.commitTransaction();

    } catch (error) {
      await queryRunner.rollbackTransaction();
      throw error;
    } finally {
      await queryRunner.release();
    }
  }

  // Log authentication events
  private async logAuthEvent(
    userId: number,
    eventType: string,
    manager?: EntityManager
  ) {
    const eventLog = this.authEventLogRepository.create({
      userId,
      eventType,
      ipAddress: this.requestContext.ip,
      userAgent: this.requestContext.userAgent
    });

    await this.authEventLogRepository.save(eventLog);
  }

  // Send verification email
  private async sendVerificationEmail(user: User, token: string) {
    await this.mailerService.sendMail({
      to: user.email,
      subject: 'Verify Your Email',
      template: 'email-verification',
      context: {
        name: user.name,
        verificationUrl: `${this.configService.get('APP_URL')}/auth/verify-email?token=${token}`
      }
    });
  }
}