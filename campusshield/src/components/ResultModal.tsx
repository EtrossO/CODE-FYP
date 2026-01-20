
import React from 'react';
import type { ScanResult } from '../types';
import { SafetyStatusValues } from '../types';

interface ResultModalProps {
  result: ScanResult | null;
  onClose: () => void;
}

const ResultModal: React.FC<ResultModalProps> = ({ result, onClose }) => {
  if (!result) return null;

  const statusTheme = {
    [SafetyStatusValues.SAFE]: {
      color: 'text-emerald-400',
      bg: 'bg-emerald-500/20',
      border: 'border-emerald-500/50',
      icon: (
        <svg className="w-12 h-12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
      )
    },
    [SafetyStatusValues.SUSPICIOUS]: {
      color: 'text-amber-400',
      bg: 'bg-amber-500/20',
      border: 'border-amber-500/50',
      icon: (
        <svg className="w-12 h-12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      )
    },
    [SafetyStatusValues.UNSAFE]: {
      color: 'text-rose-400',
      bg: 'bg-rose-500/20',
      border: 'border-rose-500/50',
      icon: (
        <svg className="w-12 h-12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      )
    },
    [SafetyStatusValues.LOADING]: {
        color: 'text-cyan-400',
        bg: 'bg-cyan-500/20',
        border: 'border-cyan-500/50',
        icon: (
            <div className="w-12 h-12 rounded-full border-4 border-cyan-400 border-t-transparent animate-spin"></div>
        )
    }
  };

  const theme = statusTheme[result.status];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-300">
      <div className="bg-gray-900 border border-gray-700 w-full max-w-md rounded-3xl overflow-hidden shadow-2xl">
        <div className={`p-8 text-center flex flex-col items-center gap-4 ${theme.bg}`}>
          {theme.icon}
          <h2 className={`text-3xl font-black uppercase tracking-widest ${theme.color}`}>
            {result.status}
          </h2>
          <p className="text-gray-300 text-sm max-w-xs">{result.reason}</p>
        </div>

        <div className="p-6 space-y-6">
          <div className="space-y-2">
            <h3 className="text-lg font-bold text-cyan-400">Page Details</h3>
            <div className="bg-gray-800 rounded-xl p-4 border border-gray-700">
              <p className="text-white font-bold mb-1">{result.title}</p>
              <p className="text-gray-400 text-xs line-clamp-3 mb-2">{result.description}</p>
              <p className="text-[10px] text-gray-500 truncate italic">{result.url}</p>
            </div>
          </div>

          <div className="flex gap-3">
            <button 
              onClick={onClose}
              className="flex-1 bg-gray-700 hover:bg-gray-600 text-white font-bold py-3 rounded-xl transition-all"
            >
              Close
            </button>
            {result.status !== SafetyStatusValues.UNSAFE && (
              <a 
                href={result.url} 
                target="_blank" 
                rel="noopener noreferrer"
                className="flex-1 bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-3 text-center rounded-xl transition-all shadow-lg shadow-cyan-900/40"
              >
                Visit Site
              </a>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ResultModal;
