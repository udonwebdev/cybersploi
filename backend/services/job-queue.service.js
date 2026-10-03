/**
 * Background Job Queue Service
 * Manages async tasks like scans, report generation, malware analysis
 */

const Bull = require('bull');
const config = require('../config');

class JobQueueService {
  constructor() {
    const redisConfig = {
      host: config.REDIS_HOST || 'localhost',
      port: config.REDIS_PORT || 6379,
      maxRetriesPerRequest: null,
    };

    // Create queues
    this.scanQueue = new Bull('scans', { redis: redisConfig });
    this.reportQueue = new Bull('reports', { redis: redisConfig });
    this.malwareQueue = new Bull('malware', { redis: redisConfig });
    this.remediationQueue = new Bull('remediation', { redis: redisConfig });

    this.setupProcessors();
  }

  setupProcessors() {
    // Scan job processor
    this.scanQueue.process(5, async (job) => {
      console.log('Processing scan job:', job.id);
      try {
        job.progress(10);
        // Simulate scan
        job.progress(50);
        await new Promise((r) => setTimeout(r, 2000));
        job.progress(90);
        return { success: true, scan_id: job.data.asset_id };
      } catch (error) {
        throw new Error(`Scan failed: ${error.message}`);
      }
    });

    // Report generation processor
    this.reportQueue.process(3, async (job) => {
      console.log('Processing report job:', job.id);
      try {
        job.progress(20);
        // Generate report
        job.progress(60);
        await new Promise((r) => setTimeout(r, 3000));
        job.progress(95);
        return { success: true, report_url: `/reports/${job.id}.pdf` };
      } catch (error) {
        throw new Error(`Report generation failed: ${error.message}`);
      }
    });

    // Malware analysis processor
    this.malwareQueue.process(2, async (job) => {
      console.log('Processing malware job:', job.id);
      try {
        job.progress(15);
        // Analyze malware
        job.progress(50);
        await new Promise((r) => setTimeout(r, 5000));
        job.progress(90);
        return { success: true, analysis_report: {} };
      } catch (error) {
        throw new Error(`Malware analysis failed: ${error.message}`);
      }
    });

    // Remediation processor
    this.remediationQueue.process(3, async (job) => {
      console.log('Processing remediation job:', job.id);
      try {
        job.progress(25);
        // Execute remediation
        job.progress(75);
        await new Promise((r) => setTimeout(r, 3000));
        job.progress(95);
        return { success: true, fixed_count: job.data.vulnerabilities.length };
      } catch (error) {
        throw new Error(`Remediation failed: ${error.message}`);
      }
    });

    // Setup event listeners
    this.setupEventListeners();
  }

  setupEventListeners() {
    const queues = [this.scanQueue, this.reportQueue, this.malwareQueue, this.remediationQueue];

    queues.forEach((queue) => {
      queue.on('progress', (job, progress) => {
        console.log(`Job ${job.id} progress: ${progress}%`);
      });

      queue.on('completed', (job) => {
        console.log(`Job ${job.id} completed`);
      });

      queue.on('failed', (job, err) => {
        console.error(`Job ${job.id} failed:`, err.message);
      });
    });
  }

  async addScanJob(assetId, scanType = 'full') {
    try {
      const job = await this.scanQueue.add(
        { asset_id: assetId, type: scanType },
        {
          attempts: 3,
          backoff: {type: 'exponential', delay: 2000},
          removeOnComplete: true,
        }
      );
      return { success: true, job_id: job.id, queue: 'scans' };
    } catch (error) {
      return { error: error.message };
    }
  }

  async addReportJob(reportType, filters = {}) {
    try {
      const job = await this.reportQueue.add(
        { type: reportType, filters },
        {
          attempts: 2,
          removeOnComplete: true,
        }
      );
      return { success: true, job_id: job.id, queue: 'reports' };
    } catch (error) {
      return { error: error.message };
    }
  }

  async addMalwareJob(fileHash, fileName) {
    try {
      const job = await this.malwareQueue.add(
        { file_hash: fileHash, file_name: fileName },
        {
          attempts: 3,
          timeout: 300000, // 5 minutes
          removeOnComplete: true,
        }
      );
      return { success: true, job_id: job.id, queue: 'malware' };
    } catch (error) {
      return { error: error.message };
    }
  }

  async getJobStatus(jobId, queue = 'scans') {
    try {
      const q = this[`${queue}Queue`];
      const job = await q.getJob(jobId);
      
      if (!job) {
        return { error: 'Job not found' };
      }

      const progress = job._progress || 0;
      const state = await job.getState();
      const data = job.data;
      const result = job.returnvalue;

      return {
        job_id: jobId,
        queue,
        state,
        progress,
        data,
        result,
        created_at: job.timestamp,
        processed_at: job.processedOn,
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  async getQueueStats() {
    try {
      const stats = {};
      const queues = {
        scans: this.scanQueue,
        reports: this.reportQueue,
        malware: this.malwareQueue,
        remediation: this.remediationQueue,
      };

      for (const [name, queue] of Object.entries(queues)) {
        const counts = await queue.getJobCounts();
        stats[name] = counts;
      }

      return stats;
    } catch (error) {
      return { error: error.message };
    }
  }

  async clearQueue(queueName) {
    try {
      const q = this[`${queueName}Queue`];
      await q.clean(0);
      return { success: true, message: `${queueName} queue cleared` };
    } catch (error) {
      return { error: error.message };
    }
  }
}

module.exports = new JobQueueService();
