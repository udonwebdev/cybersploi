/**
 * Cuckoo Sandbox Integration
 * Integrates with Cuckoo Sandbox for malware detonation and analysis
 */

const axios = require('axios');
const config = require('../config');

class CuckooSandboxService {
  constructor() {
    this.baseURL = config.CUCKOO_API_URL || 'http://localhost:8090';
    this.apiKey = config.CUCKOO_API_KEY;
    
    this.client = axios.create({
      baseURL: this.baseURL,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
      },
    });
  }

  async submitFile(filePath, options = {}) {
    try {
      const fd = new (require('form-data'))();
      const fs = require('fs');
      
      fd.append('file', fs.createReadStream(filePath));
      fd.append('priority', options.priority || 0);
      fd.append('timeout', options.timeout || 60);
      
      if (options.tags) {
        fd.append('tags', options.tags.join(','));
      }

      const response = await this.client.post('/tasks/create/file', fd, {
        headers: fd.getHeaders(),
      });

      return {
        success: true,
        task_id: response.data.task_id,
        status: 'submitted',
        message: 'File submitted for analysis',
      };
    } catch (error) {
      console.error('Submit file error:', error.message);
      return { error: error.message };
    }
  }

  async getTaskStatus(taskId) {
    try {
      const response = await this.client.get(`/tasks/view/${taskId}`);
      const task = response.data.task;

      return {
        task_id: taskId,
        status: task.status,
        added_on: task.added_on,
        completed_on: task.completed_on,
        timeout: task.timeout,
        priority: task.priority,
      };
    } catch (error) {
      console.error('Get task status error:', error.message);
      return { error: error.message };
    }
  }

  async getAnalysisReport(taskId) {
    try {
      const response = await this.client.get(`/tasks/report/${taskId}/json`);
      const report = response.data.report;

      return {
        task_id: taskId,
        analysis: {
          target: report.target,
          behavior: this.extractBehavvior(report.behavior),
          network: this.extractNetwork(report.network),
          signatures: this.extractSignatures(report.signatures),
          virustotal: report.virustotal,
          dropped_files: report.dropped_files || [],
          process_tree: report.processtree,
          strings: report.strings || [],
        },
        verdict: this.generateVerdict(report),
      };
    } catch (error) {
      console.error('Get report error:', error.message);
      return { error: error.message };
    }
  }

  extractBehavior(behavior) {
    if (!behavior || !behavior.processes) return { processes: [] };

    return {
      processes: behavior.processes.slice(0, 5).map((p) => ({
        process_id: p.process_id,
        process_name: p.process_name,
        calls: p.calls.length,
      })),
      total_processes: behavior.processes.length,
    };
  }

  extractNetwork(network) {
    return {
      dns_requests: network.dns?.length || 0,
      http_requests: network.http?.length || 0,
      tcp_connections: network.tcp?.length || 0,
      udp_connections: network.udp?.length || 0,
      domains: [...new Set((network.dns || []).map((d) => d.domain))],
      ips: [...new Set((network.tcp || []).map((t) => t.dst))],
    };
  }

  extractSignatures(signatures) {
    return (signatures || [])
      .filter((s) => s.severity >= 2)
      .map((s) => ({
        name: s.name,
        description: s.description,
        marks: s.marks,
        severity: s.severity,
      }));
  }

  generateVerdict(report) {
    const malwareScore = report.malscore || 0;

    if (malwareScore >= 8) return 'HIGHLY_SUSPICIOUS';
    if (malwareScore >= 5) return 'SUSPICIOUS';
    if (malwareScore >= 2) return 'LOW_RISK';
    return 'CLEAN';
  }

  async submitUrl(url, options = {}) {
    try {
      const response = await this.client.post('/tasks/create/url', {
        url,
        priority: options.priority || 0,
        timeout: options.timeout || 60,
      });

      return {
        success: true,
        task_id: response.data.task_id,
        url,
      };
    } catch (error) {
      console.error('Submit URL error:', error.message);
      return { error: error.message };
    }
  }

  async listTasks(limit = 20) {
    try {
      const response = await this.client.get(`/tasks/list?limit=${limit}`);

      return {
        tasks: response.data.tasks.map((t) => ({
          id: t.id,
          status: t.status,
          target: t.target,
          added_on: t.added_on,
          completed_on: t.completed_on,
        })),
        total: response.data.tasks.length,
      };
    } catch (error) {
      console.error('List tasks error:', error.message);
      return { error: error.message };
    }
  }

  async getStatistics() {
    try {
      const response = await this.client.get('/statistics');
      const stats = response.data;

      return {
        tasks_total: stats.tasks_total,
        tasks_completed: stats.tasks_completed,
        samples_total: stats.samples_total,
        machines_total: stats.machines_total,
        machines_available: stats.machines_available,
      };
    } catch (error) {
      console.error('Get statistics error:', error.message);
      return { error: error.message };
    }
  }

  async rescheduleTask(taskId) {
    try {
      await this.client.get(`/tasks/reschedule/${taskId}`);
      return { success: true, message: 'Task rescheduled' };
    } catch (error) {
      return { error: error.message };
    }
  }
}

module.exports = new CuckooSandboxService();
