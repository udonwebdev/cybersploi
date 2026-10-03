import React from "react";
import clsx from "clsx";

export const Card: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  children,
  className,
  ...props
}) => {
  return (
    <div
      className={clsx(
        "bg-background-card/90 border border-[#1e293b] rounded-2xl shadow-glass backdrop-blur-md overflow-hidden hover:border-[#334155] transition-all duration-300",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
};

export const CardHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  children,
  className,
  ...props
}) => {
  return (
    <div
      className={clsx(
        "p-5 border-b border-[#1e293b]/80 bg-background-subtle/40 flex items-center justify-between",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
};

export const CardTitle: React.FC<React.HTMLAttributes<HTMLHeadingElement>> = ({
  children,
  className,
  ...props
}) => {
  return (
    <h3
      className={clsx("text-sm font-mono font-bold text-slate-100 tracking-wide flex items-center gap-2", className)}
      {...props}
    >
      {children}
    </h3>
  );
};

export const CardContent: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  children,
  className,
  ...props
}) => {
  return (
    <div className={clsx("p-5", className)} {...props}>
      {children}
    </div>
  );
};

export const CardFooter: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  children,
  className,
  ...props
}) => {
  return (
    <div
      className={clsx("p-4 bg-background-subtle/60 border-t border-[#1e293b]/80 flex items-center", className)}
      {...props}
    >
      {children}
    </div>
  );
};
