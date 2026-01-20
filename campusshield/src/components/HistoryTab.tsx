
import React, { useState } from 'react';
import type { ScanResult } from '../types';
import { SafetyStatusValues } from '../types';

interface HistoryTabProps {
  history: ScanResult[];
  onClear: () => void;
  onSelect: (result: ScanResult) => void;
}

const HistoryTab: React.FC<HistoryTabProps> = ({ history, onClear, onSelect }) => {
  const [filter, setFilter] = useState<'ALL' | typeof SafetyStatusValues[keyof typeof SafetyStatusValues]>('ALL');

  const filteredHistory = history.filter(item => {
    if (filter === 'ALL') return true;
    return item.status === filter;
  });

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold text-gray-900 dark:text-white">Scan History</h2>
          <p className="text-gray-600 dark:text-gray-400 mt-1">View and manage your URL safety analysis results</p>
        </div>
        {history.length > 0 && (
          <button
            onClick={onClear}
            className="flex items-center gap-2 px-4 py-2 text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors border border-red-200 dark:border-red-800"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
            </svg>
            Clear All
          </button>
        )}
      </div>

      {/* Filter Tabs */}
      {history.length > 0 && (
        <div className="flex gap-2 p-1 bg-gray-100 dark:bg-gray-700 rounded-lg">
          {(['ALL', SafetyStatusValues.SAFE, SafetyStatusValues.SUSPICIOUS, SafetyStatusValues.UNSAFE] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`flex-1 py-2 px-4 text-sm font-medium rounded-md transition-all ${
                filter === f
                  ? 'bg-white dark:bg-gray-600 text-blue-600 dark:text-blue-400 shadow-sm'
                  : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-50 dark:hover:bg-gray-600'
              }`}
            >
              {f === 'ALL' ? 'All Results' : f.charAt(0) + f.slice(1).toLowerCase()}
            </button>
          ))}
        </div>
      )}

      {/* History List */}
      <div className="space-y-3">
        {filteredHistory.length === 0 ? (
          <div className="text-center py-12">
            <div className="w-16 h-16 bg-gray-100 dark:bg-gray-700 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg className="w-8 h-8 text-gray-400 dark:text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            </div>
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
              {history.length === 0 ? 'No scans yet' : 'No matching results'}
            </h3>
            <p className="text-gray-600 dark:text-gray-400">
              {history.length === 0
                ? 'Start by analyzing a URL to see your scan history here.'
                : 'Try adjusting your filter to see more results.'
              }
            </p>
          </div>
        ) : (
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {filteredHistory
              .sort((a, b) => b.timestamp - a.timestamp)
              .map((item) => (
                <div
                  key={item.id}
                  onClick={() => onSelect(item)}
                  className="bg-white border border-gray-200 rounded-lg p-4 hover:shadow-md hover:border-blue-300 cursor-pointer transition-all"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2">
                        <div className={`w-2 h-2 rounded-full ${
                          item.status === SafetyStatusValues.SAFE ? 'bg-green-500' :
                          item.status === SafetyStatusValues.SUSPICIOUS ? 'bg-yellow-500' :
                          'bg-red-500'
                        }`}></div>
                        <span className={`text-xs font-medium px-2 py-1 rounded-full ${
                          item.status === SafetyStatusValues.SAFE ? 'bg-green-100 text-green-800' :
                          item.status === SafetyStatusValues.SUSPICIOUS ? 'bg-yellow-100 text-yellow-800' :
                          'bg-red-100 text-red-800'
                        }`}>
                          {item.status}
                        </span>
                      </div>
                      <p className="text-sm font-medium text-gray-900 truncate mb-1">
                        {item.url}
                      </p>
                      <p className="text-xs text-gray-500">
                        {new Date(item.timestamp).toLocaleString()}
                      </p>
                      {item.reason && (
                        <p className="text-xs text-gray-600 mt-1 line-clamp-2">
                          {item.reason}
                        </p>
                      )}
                    </div>
                    <svg className="w-5 h-5 text-gray-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 5l7 7-7 7" />
                    </svg>
                  </div>
                </div>
              ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default HistoryTab;
