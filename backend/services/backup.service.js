/**
 * Database Backup & Recovery Service
 * Automated daily backups to cloud storage (S3, GCS, etc.)
 */

const fs = require('fs').promises;
const path = require('path');
const AWS = require('aws-sdk');
const config = require('../config');

class BackupService {
  constructor() {
    this.s3 = new AWS.S3({
      accessKeyId: config.AWS_ACCESS_KEY_ID,
      secretAccessKey: config.AWS_SECRET_ACCESS_KEY,
      region: config.AWS_REGION || 'us-east-1',
    });
    this.bucket = config.BACKUP_BUCKET || 'cybersploi-backups';
  }

  async backupDatabase() {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const backupFileName = `db-backup-${timestamp}.sql`;
      const backupPath = path.join('/tmp', backupFileName);

      // Backup PostgreSQL
      const { exec } = require('child_process');
      const dbUrl = config.DATABASE_URL;

      const command = `pg_dump ${dbUrl} > ${backupPath}`;

      await new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
          if (error) reject(error);
          else resolve();
        });
      });

      // Upload to S3
      const fileContent = await fs.readFile(backupPath);
      const s3Params = {
        Bucket: this.bucket,
        Key: `database/${backupFileName}`,
        Body: fileContent,
        ServerSideEncryption: 'AES256',
        Metadata: {
          'backup-date': new Date().toISOString(),
        },
      };

      const result = await this.s3.upload(s3Params).promise();

      // Clean up local file
      await fs.unlink(backupPath);

      console.log('Database backup completed:', result.Key);
      return {
        success: true,
        backup_file: backupFileName,
        s3_location: result.Location,
        timestamp,
      };
    } catch (error) {
      console.error('Backup error:', error);
      return { error: error.message };
    }
  }

  async listBackups(limit = 10) {
    try {
      const params = {
        Bucket: this.bucket,
        Prefix: 'database/',
        MaxKeys: limit,
      };

      const data = await this.s3.listObjectsV2(params).promise();

      return {
        backups: data.Contents.map((obj) => ({
          name: obj.Key.split('/')[1],
          size: `${(obj.Size / 1024 / 1024).toFixed(2)} MB`,
          created_at: obj.LastModified,
          storage_class: obj.StorageClass,
        })),
        total: data.Contents.length,
      };
    } catch (error) {
      console.error('List backups error:', error);
      return { error: error.message };
    }
  }

  async restoreDatabase(backupFileName) {
    try {
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const backupPath = path.join('/tmp', `${backupFileName}-${timestamp}`);

      // Download from S3
      const s3Params = {
        Bucket: this.bucket,
        Key: `database/${backupFileName}`,
      };

      const data = await this.s3.getObject(s3Params).promise();
      await fs.writeFile(backupPath, data.Body);

      // Restore to PostgreSQL
      const { exec } = require('child_process');
      const dbUrl = config.DATABASE_URL;

      const command = `psql ${dbUrl} < ${backupPath}`;

      await new Promise((resolve, reject) => {
        exec(command, (error) => {
          if (error) reject(error);
          else resolve();
        });
      });

      // Clean up
      await fs.unlink(backupPath);

      console.log('Database restore completed from:', backupFileName);
      return {
        success: true,
        message: 'Database restored successfully',
        restored_from: backupFileName,
      };
    } catch (error) {
      console.error('Restore error:', error);
      return { error: error.message };
    }
  }

  async scheduleBackups(interval = 'daily') {
    // Schedule using node-cron
    const cron = require('node-cron');

    const schedules = {
      hourly: '0 * * * *',
      daily: '0 2 * * *', // 2 AM daily
      weekly: '0 2 * * 0', // 2 AM Sunday
    };

    const schedule = schedules[interval] || schedules.daily;

    cron.schedule(schedule, async () => {
      console.log(`Running ${interval} backup...`);
      const result = await this.backupDatabase();
      if (result.success) {
        console.log('✓ Backup successful');
      } else {
        console.error('✗ Backup failed:', result.error);
      }
    });

    return { success: true, message: `${interval} backups scheduled`, schedule };
  }

  async cleanupOldBackups(daysOld = 30) {
    try {
      const params = {
        Bucket: this.bucket,
        Prefix: 'database/',
      };

      const data = await this.s3.listObjectsV2(params).promise();
      const now = new Date();
      let deletedCount = 0;

      for (const obj of data.Contents) {
        const daysDiff = Math.floor((now - obj.LastModified) / (1000 * 60 * 60 * 24));
        if (daysDiff > daysOld) {
          await this.s3.deleteObject({
            Bucket: this.bucket,
            Key: obj.Key,
          }).promise();
          deletedCount++;
        }
      }

      return {
        success: true,
        deleted_backups: deletedCount,
        older_than_days: daysOld,
      };
    } catch (error) {
      console.error('Cleanup error:', error);
      return { error: error.message };
    }
  }

  async getBackupStats() {
    try {
      const backups = await this.listBackups(100);
      let totalSize = 0;

      if (backups.backups) {
        backups.backups.forEach((backup) => {
          const sizeStr = backup.size.split(' ')[0];
          totalSize += parseFloat(sizeStr);
        });
      }

      return {
        total_backups: backups.total,
        total_size_mb: totalSize.toFixed(2),
        last_backup: backups.backups?.[0]?.created_at,
        bucket: this.bucket,
      };
    } catch (error) {
      return { error: error.message };
    }
  }
}

module.exports = new BackupService();
