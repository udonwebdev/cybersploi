import { apiClient } from "./client";

export interface SystemHealth {
  success: boolean;
  status: string;
  service: string;
  version: string;
  port: number;
  timestamp: string;
}

export interface SystemMetrics {
  status: string;
  service: string;
  uptime: number;
  memory: {
    rss: string;
    heapTotal: string;
    heapUsed: string;
  };
  platform: string;
  nodeVersion: string;
}

export const systemApi = {
  getHealth: async (): Promise<SystemHealth> => {
    const res = await apiClient.get("/health");
    return res.data;
  },

  getMetrics: async (): Promise<SystemMetrics> => {
    const res = await apiClient.get("/metrics");
    return res.data;
  },
};
