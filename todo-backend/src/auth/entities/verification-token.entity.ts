import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn, ManyToOne } from 'typeorm';
import { User } from './auth.entity';
import { ApiProperty } from '@nestjs/swagger';

@Entity()
export class VerificationToken {
  @ApiProperty({ example: 1, description: 'Unique identifier' })    
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ example: 'abc123', description: 'Verification token' })
  @Column()
  token: string;

  @ApiProperty({ type: () => User, description: 'User associated with the token' })
  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  user: User;

  @ApiProperty({ description: 'User identifier' })
  @Column()
  userId: number;

  @ApiProperty({ description: 'Creation timestamp' })
  @CreateDateColumn()
  createdAt: Date;

  @ApiProperty({ description: 'Expiration timestamp' })
  @Column()
  expiresAt: Date;

  @ApiProperty({ description: 'Type of verification token' })
  @Column()
  type: 'email_verification' | 'password_reset';
}