import React from "react";

export default function DashboardLoading() {
  return (
    <div className="space-y-6 animate-pulse py-4">
      <div className="h-8 bg-background-card border border-border rounded-md w-1/4"></div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="h-28 bg-background-card border border-border rounded-lg"></div>
        ))}
      </div>
      <div className="h-96 bg-background-card border border-border rounded-lg"></div>
    </div>
  );
}
