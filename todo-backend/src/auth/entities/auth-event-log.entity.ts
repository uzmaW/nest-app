import { 
    Entity, 
    Column, 
    PrimaryGeneratedColumn, 
    CreateDateColumn,
    ManyToOne,
    JoinColumn
  } from 'typeorm';
  import { User } from './auth.entity';
import { ApiProperty } from '@nestjs/swagger';
  
  @Entity('auth_event_logs')
  export class AuthEventLog {
    @ApiProperty({ example: 1, description: 'Unique identifier' })
    @PrimaryGeneratedColumn()
    id: number;
  
    @ApiProperty({ example: 1, description: 'User ID' })
    @Column()
    userId: number;
    
    @ApiProperty({ example: 'login', description: 'Event type' })
    @Column()
    eventType: string;
  
    @ApiProperty({ example: '192.168.1.1', description: 'IP address' })
    @Column({ nullable: true })
    ipAddress: string;
  
    @ApiProperty({ example: 'Mozilla/5.0', description: 'User agent' })
    @Column({ nullable: true })
    userAgent: string;
  
    @ApiProperty({ example: 'success', description: 'Status' })
    @Column()
    status: string;

    @ApiProperty({ example: 'Login successful', description: 'Message' })
    @Column({ nullable: true })
    message: string;

    @ApiProperty({ example: 'en', description: 'user logs' })
    @ManyToOne(() => User, user => user.authEventLogs)
    @JoinColumn({ name: 'userId' })
    user: User;
  
    @ApiProperty({ example: '2023-01-01T00:00:00.000Z', description: 'Created at' })
    @CreateDateColumn()
    createdAt: Date;
  }