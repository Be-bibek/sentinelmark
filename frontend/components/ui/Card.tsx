import React from "react";
import { twMerge } from "tailwind-merge";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export function Card({ children, className, ...props }: CardProps) {
  return (
    <div 
      className={twMerge(
        "dark:bg-[#0c0c0c] bg-white border dark:border-white/10 border-zinc-200 rounded-xl shadow-sm",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}
