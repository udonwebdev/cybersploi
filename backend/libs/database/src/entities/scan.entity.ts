import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn } from 'typeorm';

@Entity('scans')
export class Scan {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  organizationId: string;

  @Column()
  assetId: string;

  @Column()
  type: string; // 'full', 'quick', 'custom'

  @Column({ default: 'pending' })
  status: string; // 'pending', 'running', 'completed', 'failed'

  @Column({ type: 'int', default: 0 })
  progress: number;

  @Column({ type: 'text', nullable: true })
  configuration: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  completedAt: Date;
}
