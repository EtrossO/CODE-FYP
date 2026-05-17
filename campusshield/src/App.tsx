import { useState, useEffect } from 'react';
import ScannerTab from './components/ScannerTab';
import HistoryTab from './components/HistoryTab';
import Sidebar from './components/Sidebar';
import type { ScanResult } from './types';
import { SafetyStatusValues } from './types';
import { analyzeLinkSafety } from './services/geminiService';
import { db } from './db/database';

export default function App() {
  // Simple state for switching tabs
  const [activeTab, setActiveTab] = useState<'scanner' | 'history'>('scanner');
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isDarkMode, setIsDarkMode] = useState(true);

  // Load theme preference from localStorage
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
      setIsDarkMode(savedTheme === 'dark');
    } else {
      // Check system preference
      setIsDarkMode(window.matchMedia('(prefers-color-scheme: dark)').matches);
    }
  }, []);

  // Load scan history from IndexedDB on mount
  useEffect(() => {
    db.scanHistory.orderBy('timestamp').reverse().toArray().then(setHistory);
  }, []);

  // Apply theme to document
  useEffect(() => {
    if (isDarkMode) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('theme', 'light');
    }
  }, [isDarkMode]);

  const toggleTheme = () => {
    setIsDarkMode(!isDarkMode);
  };

  const handleCheck = async (url: string): Promise<ScanResult> => {
    setIsLoading(true);
    try {
      const analysisResult = await analyzeLinkSafety(url);
      const result: ScanResult = {
        id: Date.now().toString(),
        url,
        status: analysisResult.status,
        timestamp: Date.now(),
        reason: analysisResult.reason,
        title: analysisResult.title,
        description: analysisResult.description,
      };
      await db.scanHistory.add(result);
      setHistory(prev => [result, ...prev]);
      setIsLoading(false);
      return result;
    } catch (error) {
      console.error('Analysis failed:', error);
      const result: ScanResult = {
        id: Date.now().toString(),
        url,
        status: SafetyStatusValues.SUSPICIOUS,
        timestamp: Date.now(),
        reason: 'Analysis failed. Please try again.',
      };
      await db.scanHistory.add(result);
      setHistory(prev => [result, ...prev]);
      setIsLoading(false);
      return result;
    }
  };

  const handleClearHistory = async () => {
    await db.scanHistory.clear();
    setHistory([]);
  };

  const handleSelectResult = (result: ScanResult) => {
    // TODO: Handle selecting a result
    console.log('Selected result:', result);
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 dark:from-gray-900 dark:via-gray-900 dark:to-gray-800 transition-colors duration-300">
      <div className="max-w-6xl mx-auto px-4 py-8">
        {/* Header */}
        <header className="text-center mb-12 relative">
          <div className="flex items-center justify-between sm:justify-center gap-4 mb-6 relative">
            {/* Mobile: Horizontal alignment with buttons */}
            <div className="sm:hidden flex items-center justify-between w-full">
            <button
              onClick={() => setIsSidebarOpen(true)}
              className="p-3 bg-blue-600 hover:bg-blue-700 dark:bg-blue-600 dark:hover:bg-blue-700 text-white rounded-xl shadow-lg transition-colors duration-200"
              title="Open UPTM Resources"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>

            {/* Logo and Title - inline with buttons */}
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 bg-blue-600 rounded-2xl flex items-center justify-center shadow-lg">
                <img src="/logo uptm 1.png" alt="Campus Shield Logo" className="w-full h-full object-cover rounded-2xl" />
              </div>
              <div>
                <h1 className="text-2xl font-light text-gray-900 dark:text-white mb-2">
                  Campus Shield
                </h1>
                <div className="h-1 w-24 bg-blue-600 rounded-full mx-auto"></div>
              </div>
            </div>

            <button
              onClick={toggleTheme}
              className="p-3 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-800 dark:text-gray-200 rounded-xl shadow-lg transition-colors duration-200"
              title={isDarkMode ? "Switch to Light Mode" : "Switch to Dark Mode"}
            >
              {isDarkMode ? (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              ) : (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                </svg>
              )}
            </button>
            </div>

            {/* Desktop: Logo and Title */}
            <div className="hidden sm:flex items-center gap-4">
              <div className="w-16 h-16 bg-blue-600 rounded-2xl flex items-center justify-center shadow-lg">
                <img src="/logo uptm 1.png" alt="Campus Shield Logo" className="w-full h-full object-cover rounded-2xl" />
              </div>
              <div>
                <h1 className="text-4xl font-light text-gray-900 dark:text-white mb-2">
                  Campus Shield
                </h1>
                <div className="h-1 w-24 bg-blue-600 rounded-full mx-auto"></div>
              </div>
            </div>

            {/* Desktop: Buttons positioned with gaps */}
            <button
              onClick={() => setIsSidebarOpen(true)}
              className="hidden sm:block absolute left-4 top-1/2 -translate-y-1/2 p-3 bg-blue-600 hover:bg-blue-700 dark:bg-blue-600 dark:hover:bg-blue-700 text-white rounded-xl shadow-lg transition-colors duration-200"
              title="Open UPTM Resources"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
            <button
              onClick={toggleTheme}
              className="hidden sm:block absolute right-4 top-1/2 -translate-y-1/2 p-3 bg-gray-200 hover:bg-gray-300 dark:bg-gray-700 dark:hover:bg-gray-600 text-gray-800 dark:text-gray-200 rounded-xl shadow-lg transition-colors duration-200"
              title={isDarkMode ? "Switch to Light Mode" : "Switch to Dark Mode"}
            >
              {isDarkMode ? (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              ) : (
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
                </svg>
              )}
            </button>
          </div>
          <p className="text-lg sm:text-xl text-gray-600 dark:text-gray-300 max-w-3xl mx-auto leading-relaxed px-4">
            AI-powered URL scanner blocking phishing, malware, and dangerous links instantly.
          </p>
        </header>

        {/* Navigation */}
        <nav className="flex justify-center mb-8">
          <div className="bg-white dark:bg-gray-800 p-1 rounded-xl shadow-sm border border-gray-200 dark:border-gray-700 w-full max-w-md">
            <div className="flex gap-1">
              <button
                onClick={() => setActiveTab('scanner')}
                className={`flex-1 px-4 sm:px-8 py-3 rounded-lg font-medium transition-all duration-200 text-sm sm:text-base ${
                  activeTab === 'scanner'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700'
                }`}
              >
                🔍 Scan URL
              </button>
              <button
                onClick={() => setActiveTab('history')}
                className={`flex-1 px-4 sm:px-8 py-3 rounded-lg font-medium transition-all duration-200 text-sm sm:text-base ${
                  activeTab === 'history'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-700'
                }`}
              >
                📋 History ({history.length})
              </button>
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main className="bg-white dark:bg-gray-800 rounded-2xl shadow-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
          <div className="p-4 sm:p-8">
            {activeTab === 'scanner' ? (
              <ScannerTab onCheck={handleCheck} isLoading={isLoading} />
            ) : (
              <HistoryTab history={history} onClear={handleClearHistory} onSelect={handleSelectResult} />
            )}
          </div>
        </main>

        {/* Footer */}
        <footer className="text-center mt-16 text-gray-500 dark:text-gray-400 px-4">
          <div className="flex flex-col sm:flex-row items-center justify-center gap-2 mb-2">
            <span className="text-sm">Powered by</span>
            <div className="flex items-center gap-1">
              <img src="/logo uptm 1.png" alt="UPTM Logo" className="w-12 h-8 sm:w-15 sm:h-10 rounded-md" />
              <span className="text-sm font-medium">UPTM Campus Shield</span>
            </div>
          </div>
          <p className="text-xs">
            Built for campus safety • Advanced threat detection
          </p>
        </footer>
      </div>

      {/* Sidebar */}
      <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />
    </div>
  );
}