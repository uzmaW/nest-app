import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn } from 'typeorm';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

@Entity()
export class TokenBlacklist {
     
  @ApiProperty({ example: 1, description: 'Unique identifier' })
  @PrimaryGeneratedColumn()
  id: number;

  @ApiProperty({ example: 'string', description: 'Token' })
  @Column()
  token: string;

  @ApiProperty({ example: '2023-05-01T12:00:00Z', description: 'Creation date' })
  @CreateDateColumn()
  createdAt: Date;

  @ApiPropertyOptional({ example: '2023-05-01T12:00:00Z', description: 'Expiration date' })
  @Column({ type: 'timestamp' })
  expiresAt: Date;
}