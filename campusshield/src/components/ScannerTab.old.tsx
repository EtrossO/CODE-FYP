import React, { useState, useRef, useEffect, useCallback } from 'react';
import jsQR from 'jsqr';
import type { ScanResult } from '../types';
import { SafetyStatusValues } from '../types';

interface ScannerTabProps {
  onCheck: (url: string) => Promise<ScanResult>;
  isLoading: boolean;
}

// ─── Status theme helpers ────────────────────────────────────────────────────
const STATUS_THEME = {
  [SafetyStatusValues.SAFE]: {
    icon: '✅',
    label: 'Safe URL',
    badge: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
    card: 'border-green-300 dark:border-green-700 bg-green-50 dark:bg-green-900/20',
    dot: 'bg-green-500',
    iconBg: 'bg-green-100 dark:bg-green-900/40',
    iconColor: 'text-green-600 dark:text-green-400',
  },
  [SafetyStatusValues.SUSPICIOUS]: {
    icon: '⚠️',
    label: 'Suspicious URL',
    badge: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300',
    card: 'border-yellow-300 dark:border-yellow-700 bg-yellow-50 dark:bg-yellow-900/20',
    dot: 'bg-yellow-500',
    iconBg: 'bg-yellow-100 dark:bg-yellow-900/40',
    iconColor: 'text-yellow-600 dark:text-yellow-400',
  },
  [SafetyStatusValues.UNSAFE]: {
    icon: '🚫',
    label: 'Unsafe URL',
    badge: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
    card: 'border-red-300 dark:border-red-700 bg-red-50 dark:bg-red-900/20',
    dot: 'bg-red-500',
    iconBg: 'bg-red-100 dark:bg-red-900/40',
    iconColor: 'text-red-600 dark:text-red-400',
  },
  [SafetyStatusValues.LOADING]: {
    icon: '⏳',
    label: 'Analyzing…',
    badge: 'bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300',
    card: 'border-blue-300 dark:border-blue-700 bg-blue-50 dark:bg-blue-900/20',
    dot: 'bg-blue-500',
    iconBg: 'bg-blue-100 dark:bg-blue-900/40',
    iconColor: 'text-blue-600 dark:text-blue-400',
  },
};

// ─── SVG Icons ───────────────────────────────────────────────────────────────
const IconShield = () => (
  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
      d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

const IconWarning = () => (
  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
  </svg>
);

const IconDanger = () => (
  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
      d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const IconCamera = () => (
  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
      d="M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9z" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15 13a3 3 0 11-6 0 3 3 0 016 0z" />
  </svg>
);

const IconUpload = () => (
  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
      d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
  </svg>
);

// ─── Result icon by status ────────────────────────────────────────────────────
function StatusIcon({ status }: { status: ScanResult['status'] }) {
  const t = STATUS_THEME[status] ?? STATUS_THEME[SafetyStatusValues.SUSPICIOUS];
  return (
    <div className={`w-12 h-12 rounded-full flex items-center justify-center flex-shrink-0 ${t.iconBg}`}>
      <span className={t.iconColor}>
        {status === SafetyStatusValues.SAFE && <IconShield />}
        {status === SafetyStatusValues.SUSPICIOUS && <IconWarning />}
        {status === SafetyStatusValues.UNSAFE && <IconDanger />}
        {status === SafetyStatusValues.LOADING && (
          <div className="w-6 h-6 border-2 border-current border-t-transparent rounded-full animate-spin" />
        )}
      </span>
    </div>
  );
}

// ─── Result Card ─────────────────────────────────────────────────────────────
function ResultCard({ result }: { result: ScanResult }) {
  const t = STATUS_THEME[result.status] ?? STATUS_THEME[SafetyStatusValues.SUSPICIOUS];
  return (
    <div className={`rounded-xl border-2 p-5 shadow-sm transition-all ${t.card}`}>
      {/* Header row */}
      <div className="flex items-start gap-4">
        <StatusIcon status={result.status} />

        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <h3 className="text-base font-semibold text-gray-900 dark:text-white">
              {t.label}
            </h3>
            <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold ${t.badge}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${t.dot}`} />
              {result.status}
            </span>
          </div>

          {/* URL */}
          <p className="text-xs font-mono text-gray-500 dark:text-gray-400 break-all mb-3
                        bg-gray-100 dark:bg-gray-700/60 rounded-lg px-3 py-1.5">
            {result.url}
          </p>

          {/* Details grid */}
          <div className="space-y-2 text-sm">
            {result.reason && (
              <div className="flex gap-2">
                <span className="font-semibold text-gray-700 dark:text-gray-300 whitespace-nowrap">Analysis:</span>
                <span className="text-gray-600 dark:text-gray-400">{result.reason}</span>
              </div>
            )}
            {result.title && (
              <div className="flex gap-2">
                <span className="font-semibold text-gray-700 dark:text-gray-300 whitespace-nowrap">Title:</span>
                <span className="text-gray-600 dark:text-gray-400">{result.title}</span>
              </div>
            )}
            {result.description && (
              <div className="flex gap-2">
                <span className="font-semibold text-gray-700 dark:text-gray-300 whitespace-nowrap">Description:</span>
                <span className="text-gray-600 dark:text-gray-400">{result.description}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-600 flex items-center justify-between">
        <span className="text-xs text-gray-400 dark:text-gray-500">
          Analyzed on {new Date(result.timestamp).toLocaleString()}
        </span>
        {result.status !== SafetyStatusValues.UNSAFE && (
          <a
            href={result.url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-xs font-medium text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1"
          >
            Visit site
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </a>
        )}
      </div>
    </div>
  );
}

// ─── QR Scanner Section ───────────────────────────────────────────────────────
function QrScannerSection({
  isCameraActive,
  isVideoReady,
  videoRef,
  canvasRef,
  onStartCamera,
  onStopCamera,
  onFileUpload,
}: {
  isCameraActive: boolean;
  isVideoReady: boolean;
  videoRef: React.RefObject<HTMLVideoElement | null>;
  canvasRef: React.RefObject<HTMLCanvasElement | null>;
  onStartCamera: () => void;
  onStopCamera: () => void;
  onFileUpload: (e: React.ChangeEvent<HTMLInputElement>) => void;
}) {
  return (
    <div className="space-y-4">
      <div className="text-center">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">Scan QR Code</h3>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Use your camera or upload an image containing a QR code
        </p>
      </div>

      {isCameraActive ? (
        /* ── Live camera view ── */
        <div
          className="relative rounded-xl overflow-hidden border-2 border-blue-500 shadow-lg bg-black"
          style={{ aspectRatio: '1 / 1', minHeight: '280px' }}
        >
          {/* Video stream - critical attributes for cross-device support */}
          <video
            ref={videoRef}
            className="absolute inset-0 w-full h-full object-cover"
            playsInline
            autoPlay
            muted
            controls={false}
            style={{ 
              WebkitTransform: 'scaleX(-1)',
              transform: 'scaleX(-1)',
              WebkitUserSelect: 'none',
              userSelect: 'none'
            }}
          />
          <canvas ref={canvasRef} className="hidden" />

          {/* Loading overlay - show until video is ready */}
          {!isVideoReady && (
            <div className="absolute inset-0 bg-black/80 flex items-center justify-center pointer-events-none z-10">
              <div className="text-center">
                <div className="w-12 h-12 border-3 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
                <p className="text-white text-sm font-medium">Initializing camera...</p>
              </div>
            </div>
          )}

          {/* Dark vignette to make corners pop */}
          <div
            className="absolute inset-0 pointer-events-none"
            style={{ background: 'radial-gradient(ellipse at center, transparent 45%, rgba(0,0,0,0.55) 100%)' }}
          />

          {/* Overlay frame — uses % sizing so it scales on all screen sizes */}
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-20">
            <div className="relative" style={{ width: '65%', aspectRatio: '1 / 1' }}>

              {/* Corner brackets */}
              {([
                { pos: 'top-0 left-0',     borders: 'borderTop borderLeft',   radius: 'borderTopLeftRadius' },
                { pos: 'top-0 right-0',    borders: 'borderTop borderRight',  radius: 'borderTopRightRadius' },
                { pos: 'bottom-0 left-0',  borders: 'borderBottom borderLeft', radius: 'borderBottomLeftRadius' },
                { pos: 'bottom-0 right-0', borders: 'borderBottom borderRight', radius: 'borderBottomRightRadius' },
              ] as const).map(({ pos }, i) => (
                <div
                  key={i}
                  className={`absolute ${pos}`}
                  style={{
                    width: 28, height: 28,
                    borderColor: '#60a5fa',
                    borderStyle: 'solid',
                    borderWidth: 0,
                    ...(i === 0 && { borderTopWidth: 3, borderLeftWidth: 3, borderTopLeftRadius: 6 }),
                    ...(i === 1 && { borderTopWidth: 3, borderRightWidth: 3, borderTopRightRadius: 6 }),
                    ...(i === 2 && { borderBottomWidth: 3, borderLeftWidth: 3, borderBottomLeftRadius: 6 }),
                    ...(i === 3 && { borderBottomWidth: 3, borderRightWidth: 3, borderBottomRightRadius: 6 }),
                  }}
                />
              ))}

              {/* Sweeping scan line */}
              <style>{`
                @keyframes qr-sweep {
                  0%   { top: 8%; opacity: 1; }
                  48%  { top: 90%; opacity: 1; }
                  50%  { top: 90%; opacity: 0; }
                  52%  { top: 8%; opacity: 0; }
                  100% { top: 8%; opacity: 1; }
                }
              `}</style>
              <div
                className="absolute inset-x-0"
                style={{
                  height: 2,
                  background: 'linear-gradient(90deg, transparent, #60a5fa, #93c5fd, #60a5fa, transparent)',
                  boxShadow: '0 0 6px 1px rgba(96,165,250,0.6)',
                  animation: 'qr-sweep 2s ease-in-out infinite',
                  top: '8%',
                }}
              />
            </div>
          </div>

          {/* Close button */}
          <button
            onClick={onStopCamera}
            className="absolute top-3 right-3 bg-red-600 hover:bg-red-700 text-white p-2 rounded-full shadow-lg transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>

          <div className="absolute bottom-0 inset-x-0 py-3 text-center"
               style={{ background: 'linear-gradient(to top, rgba(0,0,0,0.65), transparent)' }}>
            <p className="text-xs text-white/90 font-medium tracking-wide">
              Point camera at QR code
            </p>
          </div>
        </div>
      ) : (
        /* ── Scan option cards ── */
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {/* Camera button */}
          <button
            onClick={onStartCamera}
            className="group flex flex-col items-center gap-3 p-6 rounded-xl border-2 border-dashed
                       border-gray-300 dark:border-gray-600
                       hover:border-blue-500 dark:hover:border-blue-400
                       hover:bg-blue-50 dark:hover:bg-blue-900/20
                       transition-all duration-200"
          >
            <div className="w-14 h-14 rounded-2xl bg-blue-100 dark:bg-blue-900/40
                            group-hover:bg-blue-200 dark:group-hover:bg-blue-800/50
                            flex items-center justify-center transition-colors">
              <span className="text-blue-600 dark:text-blue-400"><IconCamera /></span>
            </div>
            <div className="text-center">
              <p className="font-semibold text-gray-900 dark:text-white text-sm">Camera Scan</p>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">Use device camera</p>
            </div>
          </button>

          {/* Upload button */}
          <div className="relative">
            <input
              type="file"
              id="qr-upload"
              accept="image/*"
              onChange={onFileUpload}
              className="hidden"
            />
            <button
              onClick={() => document.getElementById('qr-upload')?.click()}
              className="group w-full flex flex-col items-center gap-3 p-6 rounded-xl border-2 border-dashed
                         border-gray-300 dark:border-gray-600
                         hover:border-blue-500 dark:hover:border-blue-400
                         hover:bg-blue-50 dark:hover:bg-blue-900/20
                         transition-all duration-200"
            >
              <div className="w-14 h-14 rounded-2xl bg-gray-100 dark:bg-gray-700
                              group-hover:bg-gray-200 dark:group-hover:bg-gray-600
                              flex items-center justify-center transition-colors">
                <span className="text-gray-600 dark:text-gray-300"><IconUpload /></span>
              </div>
              <div className="text-center">
                <p className="font-semibold text-gray-900 dark:text-white text-sm">Upload Image</p>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">Select from gallery</p>
              </div>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Camera error banner ─────────────────────────────────────────────────────
type CameraError =
  | { type: 'insecure' }
  | { type: 'permission' }
  | { type: 'unavailable' }
  | { type: 'unknown'; message: string };

function CameraErrorBanner({ error, onDismiss }: { error: CameraError; onDismiss: () => void }) {
  const isLocal =
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1';

  const content: Record<CameraError['type'], { title: string; body: React.ReactNode }> = {
    insecure: {
      title: 'Camera blocked — insecure connection',
      body: (
        <>
          <p className="mb-2">
            Browsers only allow camera access on <strong>https://</strong> or{' '}
            <strong>localhost</strong>. You are currently on{' '}
            <code className="bg-orange-100 dark:bg-orange-900/40 px-1 rounded text-xs">
              {window.location.origin}
            </code>
            .
          </p>
          <p className="font-semibold">Fix options:</p>
          <ul className="list-disc list-inside space-y-1 mt-1 text-xs">
            <li>
              Run Vite with HTTPS:{' '}
              <code className="bg-gray-100 dark:bg-gray-700 px-1 rounded">
                vite --https
              </code>
            </li>
            <li>
              Open the app on the same machine via{' '}
              <code className="bg-gray-100 dark:bg-gray-700 px-1 rounded">
                http://localhost:5173
              </code>{' '}
              instead of the network IP
            </li>
            <li>Use the "Upload Image" option below to scan a QR code from a file</li>
          </ul>
        </>
      ),
    },
    permission: {
      title: 'Camera permission denied',
      body: (
        <>
          <p className="mb-2">Your browser blocked camera access. To fix this:</p>
          <ul className="list-disc list-inside space-y-1 text-xs">
            <li>
              Click the <strong>camera / lock icon</strong> in your browser's address bar
            </li>
            <li>Set Camera to <strong>Allow</strong>, then reload the page</li>
            <li>Or use "Upload Image" to scan a saved QR code image instead</li>
          </ul>
        </>
      ),
    },
    unavailable: {
      title: 'No camera detected',
      body: (
        <p>
          No camera device was found on this device. Use the{' '}
          <strong>Upload Image</strong> option to scan a QR code from a file instead.
        </p>
      ),
    },
    unknown: {
      title: 'Camera could not be started',
      body: (
        <p>
          Unexpected error:{' '}
          <code className="bg-gray-100 dark:bg-gray-700 px-1 rounded text-xs">
            {(error as { type: 'unknown'; message: string }).message}
          </code>
          . Try using "Upload Image" instead.
        </p>
      ),
    },
  };

  const { title, body } = content[error.type];

  return (
    <div className="rounded-xl border-2 border-orange-300 dark:border-orange-600
                    bg-orange-50 dark:bg-orange-900/20 p-4 text-sm
                    text-orange-800 dark:text-orange-200 relative">
      <button
        onClick={onDismiss}
        className="absolute top-3 right-3 text-orange-400 hover:text-orange-600 transition-colors"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
      <div className="flex gap-3">
        <svg className="w-5 h-5 flex-shrink-0 mt-0.5 text-orange-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
        <div>
          <p className="font-semibold mb-1">{title}</p>
          <div className="text-orange-700 dark:text-orange-300 leading-relaxed">{body}</div>
          {!isLocal && error.type !== 'insecure' && (
            <p className="mt-2 text-xs text-orange-600 dark:text-orange-400">
              Tip: open on <strong>localhost</strong> for easiest camera access during development.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main ScannerTab ──────────────────────────────────────────────────────────
const ScannerTab: React.FC<ScannerTabProps> = ({ onCheck, isLoading }) => {
  const [urlInput, setUrlInput] = useState('');
  const [isCameraActive, setIsCameraActive] = useState(false);
  const [isVideoReady, setIsVideoReady] = useState(false);
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [cameraError, setCameraError] = useState<CameraError | null>(null);

  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const requestRef = useRef<number | undefined>(undefined);
  const streamRef = useRef<MediaStream | null>(null);

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setUrlInput(text);
    } catch {
      console.error('Failed to read clipboard');
    }
  };

  const startCamera = async () => {
    console.log('📱 Starting camera...');
    setCameraError(null);
    setIsVideoReady(false);

    // Camera API requires a secure context (https or localhost)
    if (!window.isSecureContext) {
      console.warn('❌ Not secure context - https or localhost required');
      setCameraError({ type: 'insecure' });
      return;
    }

    // navigator.mediaDevices is undefined on insecure origins too
    if (!navigator.mediaDevices?.getUserMedia) {
      console.warn('❌ getUserMedia not available');
      setCameraError({ type: 'unavailable' });
      return;
    }

    try {
      console.log('🔐 Requesting camera permission...');
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { 
          facingMode: 'environment',
          width: { ideal: 1280 },
          height: { ideal: 720 }
        },
      });
      
      console.log('✅ Camera stream obtained, tracks:', stream.getTracks().length);
      streamRef.current = stream;
      
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.setAttribute('playsinline', 'true');
        videoRef.current.setAttribute('autoplay', 'true');
        videoRef.current.setAttribute('muted', 'true');
        videoRef.current.muted = true;
        
        // With autoplay, the video should start automatically
        // But we'll also call play() for extra safety
        const playPromise = videoRef.current.play();
        if (playPromise !== undefined) {
          playPromise
            .then(() => {
              console.log('▶️ Video playing successfully');
              // Small delay to ensure video is really rendering
              setTimeout(() => {
                setIsVideoReady(true);
                setIsCameraActive(true);
              }, 300);
            })
            .catch((err) => {
              console.error('❌ Video play error:', err);
              setCameraError({ type: 'unknown', message: 'Failed to play video stream: ' + err.message });
              stopCamera();
            });
        } else {
          // For browsers that don't return a promise, set ready immediately
          setTimeout(() => {
            setIsVideoReady(true);
            setIsCameraActive(true);
          }, 300);
        }
      }
    } catch (err) {
      const error = err as Error;
      console.error('❌ Camera error:', error.name, error.message);
      const name = error.name;
      if (name === 'NotAllowedError' || name === 'PermissionDeniedError') {
        setCameraError({ type: 'permission' });
      } else if (name === 'NotFoundError' || name === 'DevicesNotFoundError') {
        setCameraError({ type: 'unavailable' });
      } else {
        setCameraError({ type: 'unknown', message: error.message });
      }
    }
  };

  const stopCamera = () => {
    console.log('⏹️ Stopping camera...');
    if (streamRef.current) {
      streamRef.current.getTracks().forEach(t => {
        t.stop();
        console.log('🛑 Stopped track:', t.kind);
      });
      streamRef.current = null;
    }
    if (videoRef.current?.srcObject) {
      videoRef.current.srcObject = null;
    }
    setIsCameraActive(false);
    setIsVideoReady(false);
    if (requestRef.current) cancelAnimationFrame(requestRef.current);
  };

  const tick = useCallback(() => {
    const video = videoRef.current;
    const canvas = canvasRef.current;
    
    if (!video || !canvas) {
      requestRef.current = requestAnimationFrame(() => tick());
      return;
    }

    // Check if video has data - use a more lenient check
    if (video.readyState >= video.HAVE_CURRENT_DATA) {
      try {
        const ctx = canvas.getContext('2d');
        if (!ctx) {
          requestRef.current = requestAnimationFrame(() => tick());
          return;
        }

        // Set canvas to match video dimensions
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;

        // Draw current video frame
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

        // Try to detect QR code with both inversion attempts
        const code = jsQR(imageData.data, imageData.width, imageData.height, {
          inversionAttempts: 'attemptBoth',
        });

        if (code?.data) {
          console.log('✅ QR code detected:', code.data);
          stopCamera();
          handleCheckUrl(code.data);
          return;
        }
      } catch (err) {
        console.error('❌ Error during QR scanning:', err);
      }
    } else {
      console.debug('⏳ Video not ready yet, readyState:', video.readyState);
    }

    requestRef.current = requestAnimationFrame(() => tick());
  }, []);

  useEffect(() => {
    if (isCameraActive && isVideoReady) {
      console.log('🎥 Starting QR scan animation frame');
      requestRef.current = requestAnimationFrame(() => tick());
    }
    return () => { 
      if (requestRef.current) cancelAnimationFrame(requestRef.current); 
    };
  }, [isCameraActive, isVideoReady, tick]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      stopCamera();
    };
  }, []);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const img = new Image();
      img.onload = () => {
        const canvas = document.createElement('canvas');
        canvas.width = img.width;
        canvas.height = img.height;
        const ctx = canvas.getContext('2d');
        if (ctx) {
          ctx.drawImage(img, 0, 0);
          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height);
          if (code) {
            handleCheckUrl(code.data);
          } else {
            alert('No QR code found in this image.');
          }
        }
      };
      img.src = event.target?.result as string;
    };
    reader.readAsDataURL(file);
  };

  const handleCheckUrl = async (url: string) => {
    setCurrentResult(null);
    const result = await onCheck(url);
    setCurrentResult(result);
  };

  return (
    <div className="max-w-2xl mx-auto space-y-8">
      {/* ── URL Input ── */}
      <div className="space-y-4">
        <div className="text-center">
          <h2 className="text-2xl font-semibold text-gray-900 dark:text-white mb-1">URL Safety Scanner</h2>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Enter a URL to analyze for potential security threats
          </p>
        </div>

        <div className="relative">
          <input
            type="url"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && urlInput.trim() && !isLoading) handleCheckUrl(urlInput.trim()); }}
            placeholder="https://example.com"
            className="w-full pl-4 pr-12 py-3 rounded-xl border border-gray-300 dark:border-gray-600
                       bg-white dark:bg-gray-700 text-gray-900 dark:text-white
                       placeholder-gray-400 dark:placeholder-gray-500
                       focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none transition"
          />
          <button
            onClick={handlePaste}
            title="Paste from clipboard"
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-blue-500 transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
            </svg>
          </button>
        </div>

        <button
          onClick={() => { if (urlInput.trim()) handleCheckUrl(urlInput.trim()); }}
          disabled={isLoading || !urlInput.trim()}
          className="w-full flex items-center justify-center gap-2 py-3 px-6 rounded-xl font-semibold
                     bg-blue-600 hover:bg-blue-700 text-white
                     disabled:bg-gray-200 dark:disabled:bg-gray-700
                     disabled:text-gray-400 dark:disabled:text-gray-500
                     disabled:cursor-not-allowed transition-colors"
        >
          {isLoading ? (
            <>
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              Analyzing URL…
            </>
          ) : (
            <>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2"
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Analyze URL
            </>
          )}
        </button>
      </div>

      {/* ── Divider ── */}
      <div className="relative">
        <div className="absolute inset-0 flex items-center">
          <div className="w-full border-t border-gray-200 dark:border-gray-700" />
        </div>
        <div className="relative flex justify-center">
          <span className="px-4 bg-white dark:bg-gray-800 text-xs font-medium text-gray-400 dark:text-gray-500 uppercase tracking-widest">
            or scan a QR code
          </span>
        </div>
      </div>

      {/* ── QR Scanner ── */}
      {cameraError && (
        <CameraErrorBanner error={cameraError} onDismiss={() => setCameraError(null)} />
      )}
      <QrScannerSection
        isCameraActive={isCameraActive}
        isVideoReady={isVideoReady}
        videoRef={videoRef}
        canvasRef={canvasRef}
        onStartCamera={startCamera}
        onStopCamera={stopCamera}
        onFileUpload={handleFileUpload}
      />

      {/* ── Result Card ── */}
      {isLoading && !currentResult && (
        <div className="rounded-xl border-2 border-blue-300 dark:border-blue-700 bg-blue-50 dark:bg-blue-900/20 p-6 flex items-center gap-4">
          <div className="w-10 h-10 border-4 border-blue-500 border-t-transparent rounded-full animate-spin flex-shrink-0" />
          <div>
            <p className="font-semibold text-blue-700 dark:text-blue-300">Analyzing URL…</p>
            <p className="text-sm text-blue-500 dark:text-blue-400">Checking for threats, please wait</p>
          </div>
        </div>
      )}

      {currentResult && !isLoading && <ResultCard result={currentResult} />}
    </div>
  );
};

export default ScannerTab;