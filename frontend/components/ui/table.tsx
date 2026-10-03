import React from "react";
import clsx from "clsx";

export const Table: React.FC<React.TableHTMLAttributes<HTMLTableElement>> = ({
  children,
  className,
  ...props
}) => {
  return (
    <div className="w-full overflow-x-auto border border-border rounded-lg">
      <table className={clsx("w-full text-left text-sm", className)} {...props}>
        {children}
      </table>
    </div>
  );
};

export const TableHead: React.FC<React.HTMLAttributes<HTMLTableSectionElement>> = ({
  children,
  className,
  ...props
}) => {
  return (
    <thead
      className={clsx("bg-background-subtle border-b border-border text-xs uppercase font-mono text-slate-400 tracking-wider", className)}
      {...props}
    >
      {children}
    </thead>
  );
};

export const TableBody: React.FC<React.HTMLAttributes<HTMLTableSectionElement>> = ({
  children,
  className,
  ...props
}) => {
  return (
    <tbody className={clsx("divide-y divide-border-muted", className)} {...props}>
      {children}
    </tbody>
  );
};

export const TableRow: React.FC<React.HTMLAttributes<HTMLTableRowElement>> = ({
  children,
  className,
  ...props
}) => {
  return (
    <tr
      className={clsx("hover:bg-white/[0.02] transition-colors", className)}
      {...props}
    >
      {children}
    </tr>
  );
};

export const TableCell: React.FC<React.TdHTMLAttributes<HTMLTableCellElement>> = ({
  children,
  className,
  ...props
}) => {
  return (
    <td className={clsx("p-4 text-slate-200 align-middle", className)} {...props}>
      {children}
    </td>
  );
};

export const TableHeaderCell: React.FC<React.ThHTMLAttributes<HTMLTableCellElement>> = ({
  children,
  className,
  ...props
}) => {
  return (
    <th className={clsx("p-4 font-medium text-slate-400 align-middle", className)} {...props}>
      {children}
    </th>
  );
};
