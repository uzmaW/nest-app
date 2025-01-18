import { 
  Entity, 
  Column, 
  PrimaryGeneratedColumn, 
  CreateDateColumn, 
  UpdateDateColumn,
  OneToMany
} from 'typeorm';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { RefreshToken } from './refresh-token.entity';
import { VerificationToken } from './verification-token.entity';
import { AuthEventLog } from './auth-event-log.entity';

@Entity('users')
export class User {
  @ApiProperty({ example: 1, description: 'Unique identifier' })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ example: 'user@example.com', description: 'User email address' })
  @Column({ unique: true })
  email: string;

  @ApiProperty({ description: 'Hashed user password' })
  @Column()
  password: string;

  @ApiProperty({ example: 'John Doe', description: 'User full name' })
  @Column()
  name: string;

  @ApiProperty({ 
    example: 'user', 
    description: 'User role',
    enum: ['admin', 'user']
  })
  @Column({ type: 'enum', enum: ['admin', 'user'], default: 'user' })
  role: string;

  @ApiProperty({ 
    example: false, 
    description: 'Email verification status' 
  })
  @Column({ default: false })
  isEmailVerified: boolean;

  @ApiProperty({ 
    example: 0, 
    description: 'Number of failed login attempts' 
  })
  @Column({ default: 0 })
  loginAttempts: number;

  @ApiPropertyOptional({ 
    description: 'Timestamp of last login attempt' 
  })
  @Column({ type: 'timestamp', nullable: true })
  lastLoginAttempt: Date;

  @ApiPropertyOptional({ 
    description: 'Account lock expiration timestamp' 
  })
  
  @Column({ type: 'timestamp', nullable: true })
  //@Column({ type: 'timestamp', nullable: true })
  lockUntil: Date;

  @ApiProperty({ type: () => [RefreshToken] })
  @OneToMany(() => RefreshToken, token => token.user)
  refreshTokens: RefreshToken[];

  @ApiProperty({ type: () => [VerificationToken] })
  @OneToMany(() => VerificationToken, token => token.user)
  verificationTokens: VerificationToken[];

  @ApiProperty({ type: () => [AuthEventLog] })
  @OneToMany(() => AuthEventLog, log => log.user)
  authEventLogs: AuthEventLog[];

  @ApiProperty({ description: 'Creation timestamp' })
  @CreateDateColumn()
  createdAt: Date;

  @ApiProperty({ description: 'Last update timestamp' })
  @UpdateDateColumn()
  updatedAt: Date;
}