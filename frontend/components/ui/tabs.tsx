"use client";

import React, { createContext, useContext, useState } from "react";
import clsx from "clsx";

export interface TabItem {
  id: string;
  label: string;
  count?: number;
}

interface TabsContextValue {
  value: string;
  onValueChange: (val: string) => void;
}

const TabsContext = createContext<TabsContextValue | null>(null);

export interface TabsProps {
  tabs?: TabItem[];
  activeTab?: string;
  onChange?: (tabId: string) => void;
  defaultValue?: string;
  value?: string;
  onValueChange?: (val: string) => void;
  className?: string;
  children?: React.ReactNode;
}

export const Tabs: React.FC<TabsProps> = ({
  tabs,
  activeTab,
  onChange,
  defaultValue,
  value: controlledValue,
  onValueChange,
  className,
  children,
}) => {
  const [internalValue, setInternalValue] = useState(
    defaultValue || (tabs && tabs[0]?.id) || ""
  );

  const currentValue = controlledValue !== undefined ? controlledValue : (activeTab !== undefined ? activeTab : internalValue);

  const handleValueChange = (val: string) => {
    if (onValueChange) onValueChange(val);
    if (onChange) onChange(val);
    if (controlledValue === undefined && activeTab === undefined) {
      setInternalValue(val);
    }
  };

  // If simple tabs array prop is used without children
  if (tabs && !children) {
    return (
      <div className={clsx("flex border-b border-cyber-border space-x-1", className)}>
        {tabs.map((tab) => {
          const isActive = tab.id === currentValue;
          return (
            <button
              key={tab.id}
              onClick={() => handleValueChange(tab.id)}
              className={clsx(
                "px-4 py-2.5 text-sm font-mono tracking-wide transition-all border-b-2 -mb-px flex items-center gap-2",
                isActive
                  ? "border-cyber-accent text-cyber-accent font-semibold"
                  : "border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700"
              )}
            >
              {tab.label}
              {tab.count !== undefined && (
                <span
                  className={clsx(
                    "text-xs px-1.5 py-0.5 rounded-full font-mono",
                    isActive
                      ? "bg-cyber-accent/20 text-cyber-accent"
                      : "bg-slate-800 text-slate-400"
                  )}
                >
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>
    );
  }

  return (
    <TabsContext.Provider value={{ value: currentValue, onValueChange: handleValueChange }}>
      <div className={clsx("w-full", className)}>{children}</div>
    </TabsContext.Provider>
  );
};

export interface TabsListProps extends React.HTMLAttributes<HTMLDivElement> {}

export const TabsList: React.FC<TabsListProps> = ({ className, children, ...props }) => {
  return (
    <div
      className={clsx(
        "inline-flex items-center gap-1 p-1 rounded-lg bg-cyber-surface border border-cyber-border",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
};

export interface TabsTriggerProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  value: string;
}

export const TabsTrigger: React.FC<TabsTriggerProps> = ({
  value,
  className,
  children,
  ...props
}) => {
  const context = useContext(TabsContext);
  const isActive = context?.value === value;

  return (
    <button
      type="button"
      onClick={() => context?.onValueChange(value)}
      className={clsx(
        "px-3 py-1.5 text-xs font-medium rounded-md transition-all flex items-center gap-2 font-mono",
        isActive
          ? "bg-cyber-bg text-cyber-accent border border-cyber-accent/40 shadow-sm"
          : "text-cyber-text-secondary hover:text-cyber-text-primary hover:bg-cyber-bg/50",
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
};

export interface TabsContentProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string;
}

export const TabsContent: React.FC<TabsContentProps> = ({
  value,
  className,
  children,
  ...props
}) => {
  const context = useContext(TabsContext);
  if (context?.value !== value) return null;

  return (
    <div className={clsx("mt-4 focus-visible:outline-none", className)} {...props}>
      {children}
    </div>
  );
};
