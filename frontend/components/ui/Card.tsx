import React from "react";
import { twMerge } from "tailwind-merge";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export function Card({ children, className, ...props }: CardProps) {
  return (
    <div 
      className={twMerge(
        "ui-card",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}
