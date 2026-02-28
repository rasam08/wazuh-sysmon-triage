import React from 'react';
import { useRouteError, isRouteErrorResponse, useNavigate } from 'react-router-dom';

export function RouteErrorFallback() {
  const error = useRouteError();
  const navigate = useNavigate();

  let title = 'Something went wrong';
  let detail = 'An unexpected error occurred while loading this page.';

  if (isRouteErrorResponse(error)) {
    title = `${error.status} - ${error.statusText || 'Error'}`;
    detail = error.data?.message ?? `The server returned a ${error.status} response.`;
  } else if (error instanceof Error) {
    detail = error.message;
  }

  return (
    <div className="min-h-[60vh] flex items-center justify-center p-8">
      <div className="max-w-lg w-full bg-gray-900 border border-gray-800 rounded-lg p-6 space-y-4">
        <div className="flex items-center gap-3">
          <span className="text-red-400 text-2xl">!</span>
          <h1 className="text-lg font-bold text-gray-100">{title}</h1>
        </div>
        <p className="text-sm text-gray-400">{detail}</p>
        <div className="flex gap-3">
          <button
            onClick={() => navigate('/dashboard')}
            className="px-4 py-2 text-sm font-medium rounded-md bg-blue-600 text-white hover:bg-blue-500 transition-colors"
          >
            Go to Dashboard
          </button>
          <button
            onClick={() => window.location.reload()}
            className="px-4 py-2 text-sm font-medium rounded-md bg-gray-800 text-gray-200 hover:bg-gray-700 transition-colors border border-gray-700"
          >
            Reload Page
          </button>
        </div>
      </div>
    </div>
  );
}
