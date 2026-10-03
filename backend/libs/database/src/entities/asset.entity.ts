import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn } from 'typeorm';

@Entity('assets')
export class Asset {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column()
  organizationId: string;

  @Column()
  type: string; // 'domain', 'ip', 'website', 'api', 'mobile_app'

  @Column()
  value: string;

  @Column({ default: 'pending' })
  verificationStatus: string;

  @Column({ nullable: true })
  verificationToken: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
