import { useState, useEffect } from 'react';
import type { ScanResult } from '../types';
import { SafetyStatusValues } from '../types';
import { getDomainStats, extractDomain, type DomainStats } from '../services/statsService';
import { db } from '../db/database';

export default function ThreatHeatmap() {
  const [stats, setStats] = useState<DomainStats[]>([]);
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);
  const [domainResults, setDomainResults] = useState<ScanResult[]>([]);
  const [search, setSearch] = useState('');

  useEffect(() => {
    getDomainStats().then(setStats);
  }, []);

  const handleDomainClick = async (domain: string) => {
    if (selectedDomain === domain) {
      setSelectedDomain(null);
      setDomainResults([]);
      return;
    }
    setSelectedDomain(domain);
    const all = await db.scanHistory.toArray();
    setDomainResults(
      all.filter((r) => extractDomain(r.url) === domain)
        .sort((a, b) => b.timestamp - a.timestamp)
    );
  };

  const totalScans = stats.reduce((s, d) => s + d.total, 0);
  const totalDomains = stats.length;
  const totalUnsafe = stats.reduce((s, d) => s + d.unsafe, 0);
  const totalSuspicious = stats.reduce((s, d) => s + d.suspicious, 0);

  const filtered = stats.filter((d) =>
    d.domain.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h2 className="text-2xl font-semibold text-gray-900 dark:text-white">
          Campus Threat Heatmap
        </h2>
        <p className="text-gray-600 dark:text-gray-400 mt-1">
          Anonymized overview of scanned domains across campus.
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <SummaryCard label="Total Scans" value={totalScans} color="blue" />
        <SummaryCard label="Domains" value={totalDomains} color="indigo" />
        <SummaryCard label="Suspicious" value={totalSuspicious} color="yellow" />
        <SummaryCard label="Unsafe" value={totalUnsafe} color="red" />
      </div>

      {/* Search */}
      <input
        type="text"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Search domain..."
        className="w-full px-4 py-2.5 rounded-xl border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition text-sm"
      />

      {/* Domain List */}
      <div className="space-y-2">
        {filtered.length === 0 ? (
          <div className="text-center py-12 text-gray-500 dark:text-gray-400">
            {stats.length === 0 ? 'No scan data yet. Start scanning URLs to see the heatmap.' : 'No domains match your search.'}
          </div>
        ) : (
          filtered.map((d) => (
            <div key={d.domain}>
              <button
                onClick={() => handleDomainClick(d.domain)}
                className={`w-full text-left bg-white dark:bg-gray-700 border rounded-xl p-4 transition-all hover:shadow-md ${
                  selectedDomain === d.domain
                    ? 'border-blue-400 dark:border-blue-500 shadow-md'
                    : 'border-gray-200 dark:border-gray-600'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-gray-900 dark:text-white text-sm truncate mr-2">
                    {d.domain}
                  </span>
                  <span className="text-xs text-gray-500 dark:text-gray-400 flex-shrink-0">
                    {d.total} scan{d.total !== 1 ? 's' : ''}
                  </span>
                </div>
                {/* Stacked bar */}
                <div className="w-full h-2.5 bg-gray-200 dark:bg-gray-600 rounded-full overflow-hidden flex">
                  {d.safe > 0 && (
                    <div
                      className="bg-green-500 h-full transition-all"
                      style={{ width: `${(d.safe / d.total) * 100}%` }}
                      title={`Safe: ${d.safe}`}
                    />
                  )}
                  {d.suspicious > 0 && (
                    <div
                      className="bg-yellow-500 h-full transition-all"
                      style={{ width: `${(d.suspicious / d.total) * 100}%` }}
                      title={`Suspicious: ${d.suspicious}`}
                    />
                  )}
                  {d.unsafe > 0 && (
                    <div
                      className="bg-red-500 h-full transition-all"
                      style={{ width: `${(d.unsafe / d.total) * 100}%` }}
                      title={`Unsafe: ${d.unsafe}`}
                    />
                  )}
                </div>
                {/* Legend */}
                <div className="flex gap-3 mt-1.5 text-[10px] text-gray-500 dark:text-gray-400">
                  {d.safe > 0 && <span>🟢 {d.safe}</span>}
                  {d.suspicious > 0 && <span>🟡 {d.suspicious}</span>}
                  {d.unsafe > 0 && <span>🔴 {d.unsafe}</span>}
                </div>
              </button>

              {/* Expanded results for selected domain */}
              {selectedDomain === d.domain && domainResults.length > 0 && (
                <div className="ml-4 mt-1 space-y-1.5 max-h-64 overflow-y-auto">
                  {domainResults.map((r) => (
                    <div
                      key={r.id}
                      className="flex items-center gap-2 bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600 rounded-lg px-3 py-2 text-xs"
                    >
                      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${
                        r.status === SafetyStatusValues.SAFE ? 'bg-green-500' :
                        r.status === SafetyStatusValues.SUSPICIOUS ? 'bg-yellow-500' : 'bg-red-500'
                      }`} />
                      <span className="flex-1 truncate text-gray-700 dark:text-gray-300">{r.url}</span>
                      <span className="text-gray-400 dark:text-gray-500 flex-shrink-0">
                        {new Date(r.timestamp).toLocaleDateString()}
                      </span>
                      <span className={`font-medium flex-shrink-0 ${
                        r.status === SafetyStatusValues.SAFE ? 'text-green-600 dark:text-green-400' :
                        r.status === SafetyStatusValues.SUSPICIOUS ? 'text-yellow-600 dark:text-yellow-400' :
                        'text-red-600 dark:text-red-400'
                      }`}>
                        {r.status}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function SummaryCard({ label, value, color }: { label: string; value: number; color: string }) {
  const colorClasses: Record<string, string> = {
    blue: 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800 text-blue-700 dark:text-blue-300',
    indigo: 'bg-indigo-50 dark:bg-indigo-900/20 border-indigo-200 dark:border-indigo-800 text-indigo-700 dark:text-indigo-300',
    yellow: 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800 text-yellow-700 dark:text-yellow-300',
    red: 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300',
  };

  return (
    <div className={`rounded-xl border p-4 ${colorClasses[color] || ''}`}>
      <p className="text-2xl font-bold">{value}</p>
      <p className="text-xs mt-0.5 opacity-80">{label}</p>
    </div>
  );
}
