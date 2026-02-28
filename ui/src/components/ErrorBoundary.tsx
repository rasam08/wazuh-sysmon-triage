import React, { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('[ErrorBoundary]', error, info.componentStack);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;

      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-950 text-gray-100 p-8">
          <div className="max-w-lg w-full bg-gray-900 border border-gray-800 rounded-lg p-6 space-y-4">
            <div className="flex items-center gap-3">
              <span className="text-red-400 text-2xl">!</span>
              <h1 className="text-lg font-bold text-gray-100">Something went wrong</h1>
            </div>
            <p className="text-sm text-gray-400">
              An unexpected error occurred. You can try recovering or reload the page.
            </p>
            {this.state.error && (
              <pre className="text-xs text-red-400/80 bg-red-950/30 border border-red-800/40 rounded p-3 overflow-auto max-h-40 whitespace-pre-wrap break-all">
                {this.state.error.message}
              </pre>
            )}
            <div className="flex gap-3">
              <button
                onClick={this.handleReset}
                className="px-4 py-2 text-sm font-medium rounded-md bg-blue-600 text-white hover:bg-blue-500 transition-colors"
              >
                Try Again
              </button>
              <button
                onClick={() => window.location.assign('/')}
                className="px-4 py-2 text-sm font-medium rounded-md bg-gray-800 text-gray-200 hover:bg-gray-700 transition-colors border border-gray-700"
              >
                Go Home
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
