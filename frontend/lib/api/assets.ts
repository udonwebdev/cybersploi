import { apiClient } from "./client";

export interface Asset {
  id: string;
  name: string;
  type: "domain" | "ip" | "cloud" | "network";
  target: string;
  criticality: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  status: "verified" | "pending" | "unverified";
  createdAt: string;
  updatedAt: string;
}

export const assetsApi = {
  getAssets: async (): Promise<Asset[]> => {
    const res = await apiClient.get("/v1/assets");
    const raw = res.data.data || res.data.assets || res.data;
    const list = Array.isArray(raw) ? raw : (raw?.assets || raw?.data || []);
    return Array.isArray(list) ? list : [];
  },

  createAsset: async (asset: {
    name: string;
    type: string;
    target: string;
    criticality?: string;
  }): Promise<Asset> => {
    const res = await apiClient.post("/v1/assets", asset);
    return res.data.data || res.data;
  },

  deleteAsset: async (id: string): Promise<void> => {
    await apiClient.delete(`/v1/assets/${id}`);
  },
};
