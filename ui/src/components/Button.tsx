import React from 'react';

type Variant = 'primary' | 'secondary' | 'danger' | 'ghost';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: 'sm' | 'md' | 'lg';
  loading?: boolean;
}

const base = 'inline-flex items-center justify-center font-medium rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-950 disabled:opacity-50 disabled:cursor-not-allowed';

const variants: Record<Variant, string> = {
  primary: 'bg-blue-600 text-white hover:bg-blue-500 focus:ring-blue-500',
  secondary: 'bg-gray-800 text-gray-200 hover:bg-gray-700 border border-gray-700 focus:ring-gray-500',
  danger: 'bg-red-700 text-white hover:bg-red-600 focus:ring-red-500',
  ghost: 'text-gray-400 hover:text-gray-200 hover:bg-gray-800 focus:ring-gray-600',
};

const sizes = {
  sm: 'px-2.5 py-1 text-xs gap-1',
  md: 'px-3.5 py-2 text-sm gap-1.5',
  lg: 'px-5 py-2.5 text-base gap-2',
};

export function Button({ variant = 'primary', size = 'md', loading, children, className = '', ...props }: ButtonProps) {
  return (
    <button className={`${base} ${variants[variant]} ${sizes[size]} ${className}`} disabled={loading || props.disabled} {...props}>
      {loading && (
        <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
        </svg>
      )}
      {children}
    </button>
  );
}
