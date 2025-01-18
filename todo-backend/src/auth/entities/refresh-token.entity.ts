import { 
  Entity, 
  Column, 
  PrimaryGeneratedColumn, 
  CreateDateColumn,
  ManyToOne,
  JoinColumn
} from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';
import { User } from './auth.entity';

@Entity('refresh_tokens')
export class RefreshToken {
  @ApiProperty({ example: 1, description: 'Unique identifier' })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ description: 'Refresh token string' })
  @Column()
  token: string;

  @ApiProperty({ example: 1, description: 'User ID' })
  @Column()
  userId: number;

  @ApiProperty({ description: 'Token expiration timestamp' })
  @Column({ type: 'timestamp' })
  expiresAt: Date;

  @ApiProperty({ 
    example: false, 
    description: 'Token revocation status' 
  })
  @Column({ default: false })
  isRevoked: boolean;

  @ApiProperty({ type: () => User })
  @ManyToOne(() => User, user => user.refreshTokens)
  @JoinColumn({ name: 'userId' })
  user: User;

  @ApiProperty({ description: 'Creation timestamp' })
  @CreateDateColumn()
  createdAt: Date;
}