"use client";

import React from "react";
import clsx from "clsx";

interface SkeletonProps {
  className?: string;
  variant?: "text" | "rect" | "circle";
  width?: string | number;
  height?: string | number;
}

export const Skeleton: React.FC<SkeletonProps> = ({
  className = "",
  variant = "rect",
  width,
  height,
}) => {
  return (
    <div
      style={{ width, height }}
      className={clsx(
        "shimmer-loading bg-slate-800/40 border border-border/40",
        variant === "circle" && "rounded-full",
        variant === "text" && "rounded h-4 w-full",
        variant === "rect" && "rounded-lg",
        className
      )}
    />
  );
};

export const DashboardSkeleton: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Top Bar Skeleton */}
      <div className="flex justify-between items-center pb-5 border-b border-border">
        <div className="space-y-2">
          <Skeleton className="h-7 w-64" />
          <Skeleton className="h-4 w-96" />
        </div>
        <div className="flex gap-3">
          <Skeleton className="h-9 w-24" />
          <Skeleton className="h-9 w-32" />
        </div>
      </div>

      {/* 4 Stat Cards Skeleton */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="p-5 rounded-xl border border-border bg-background-card/60 space-y-3">
            <div className="flex justify-between">
              <Skeleton className="h-3 w-24" />
              <Skeleton className="h-8 w-8 rounded-lg" />
            </div>
            <Skeleton className="h-8 w-16" />
            <Skeleton className="h-3 w-36" />
          </div>
        ))}
      </div>

      {/* Table & Side Panel Skeleton */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-5 rounded-xl border border-border bg-background-card/60 space-y-4">
          <Skeleton className="h-5 w-48" />
          <div className="space-y-3 pt-2">
            {[1, 2, 3, 4, 5].map((i) => (
              <Skeleton key={i} className="h-10 w-full" />
            ))}
          </div>
        </div>
        <div className="p-5 rounded-xl border border-border bg-background-card/60 space-y-4">
          <Skeleton className="h-5 w-36" />
          <div className="space-y-3">
            <Skeleton className="h-20 w-full" />
            <Skeleton className="h-24 w-full" />
          </div>
        </div>
      </div>
    </div>
  );
};
