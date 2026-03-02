import React from 'react';
import { useNavigate } from 'react-router-dom';

function NotFoundScreen() {
  const navigate = useNavigate();

  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <p className="text-6xl font-bold text-gray-700 mb-2">404</p>
      <h1 className="text-xl font-semibold text-gray-200 mb-2">Page Not Found</h1>
      <p className="text-sm text-gray-500 max-w-md mb-6">
        The page you're looking for doesn't exist or has been moved.
      </p>
      <div className="flex gap-3">
        <button
          onClick={() => navigate('/dashboard')}
          className="px-4 py-2 text-sm font-medium rounded-md bg-blue-600 text-white hover:bg-blue-500 transition-colors"
        >
          Go to Dashboard
        </button>
        <button
          onClick={() => navigate(-1)}
          className="px-4 py-2 text-sm font-medium rounded-md bg-gray-800 text-gray-200 hover:bg-gray-700 transition-colors border border-gray-700"
        >
          Go Back
        </button>
      </div>
    </div>
  );
}

export default NotFoundScreen;
