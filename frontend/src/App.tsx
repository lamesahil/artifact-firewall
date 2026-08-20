import React, { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  UploadCloud, 
  Copy, 
  Check, 
  Lock, 
  Settings, 
  AlertCircle, 
  ShieldAlert,
  FileJson,
  Trash2,
  ChevronRight
} from 'lucide-react';
import SecurityMonolith from './components/SecurityMonolith';

interface SanitizationStats {
  jwt: number;
  aws: number;
  database: number;
  generic: number;
}

interface RedactedDetail {
  type: string;
  originalSnippet: string;
  placeholder: string;
}

interface SanitizationResponse {
  fileName?: string;
  fileType?: string;
  isJson: boolean;
  originalContent: string;
  sanitizedContent: string;
  stats: SanitizationStats;
  details: RedactedDetail[];
}

const API_URL = import.meta.env.VITE_API_URL || 'https://artifact-firewall-1.onrender.com';

const COMBINED_SECRET_REGEX = /\b(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*|(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}|(?:postgres(?:ql)?|mongodb(?:\+srv)?):\/\/[^:\s]+:[^@\s]+@[^/\s]+(?::\d+)?(?:[^\s?]+)?(?:\?[^\s]+)?|xox[bapr]-[0-9a-zA-Z-]{10,64}|(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,48}|AIza[A-Za-z0-9-_]{35})\b/g;

export default function App() {
  const [activeTab, setActiveTab] = useState<'file' | 'text'>('file');
  const [rawText, setRawText] = useState('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState(false);

  // Filter Settings
  const [settings, setSettings] = useState({
    jwt: true,
    aws: true,
    database: true,
    generic: true
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<SanitizationResponse | null>(null);
  const [copied, setCopied] = useState(false);

  // Sync scroll references
  const leftScrollRef = useRef<HTMLDivElement>(null);
  const rightScrollRef = useRef<HTMLDivElement>(null);
  const activeScroller = useRef<'left' | 'right' | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleLeftScroll = () => {
    if (activeScroller.current === 'right') return;
    activeScroller.current = 'left';
    if (leftScrollRef.current && rightScrollRef.current) {
      rightScrollRef.current.scrollTop = leftScrollRef.current.scrollTop;
      rightScrollRef.current.scrollLeft = leftScrollRef.current.scrollLeft;
    }
    setTimeout(() => {
      if (activeScroller.current === 'left') activeScroller.current = null;
    }, 50);
  };

  const handleRightScroll = () => {
    if (activeScroller.current === 'left') return;
    activeScroller.current = 'right';
    if (leftScrollRef.current && rightScrollRef.current) {
      leftScrollRef.current.scrollTop = rightScrollRef.current.scrollTop;
      leftScrollRef.current.scrollLeft = rightScrollRef.current.scrollLeft;
    }
    setTimeout(() => {
      if (activeScroller.current === 'right') activeScroller.current = null;
    }, 50);
  };

  const toggleSetting = (key: keyof typeof settings) => {
    setSettings(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (file: File) => {
    const ext = file.name.split('.').pop()?.toLowerCase();
    const validExtensions = ['txt', 'json', 'har'];
    if (ext && validExtensions.includes(ext)) {
      setSelectedFile(file);
      setError(null);
    } else {
      setError('Unsupported extension. Please upload a TXT, JSON, or HAR artifact.');
      setSelectedFile(null);
    }
  };

  const clearFile = () => {
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleSanitize = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      let response;

      if (activeTab === 'file') {
        if (!selectedFile) {
          setError('Please provide an input artifact file.');
          setLoading(false);
          return;
        }

        const formData = new FormData();
        formData.append('file', selectedFile);
        formData.append('settings', JSON.stringify(settings));

        response = await fetch(`${API_URL}/api/sanitize`, {
          method: 'POST',
          body: formData
        });
      } else {
        if (!rawText.trim()) {
          setError('Please provide raw text input payload.');
          setLoading(false);
          return;
        }

        response = await fetch(`${API_URL}/api/sanitize`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            text: rawText,
            settings
          })
        });
      }

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to process artifact.');
      }

      const data: SanitizationResponse = await response.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || 'An error occurred during verification.');
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (!result) return;
    navigator.clipboard.writeText(result.sanitizedContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const renderHighlightedText = (text: string, isSanitized: boolean) => {
    if (!text) return '';

    if (isSanitized) {
      const parts = text.split('[REDACTED_SECRET]');
      return (
        <>
          {parts.map((part, index) => (
            <React.Fragment key={index}>
              {part}
              {index < parts.length - 1 && (
                <span className="highlight-redacted-secret">[REDACTED_SECRET]</span>
              )}
            </React.Fragment>
          ))}
        </>
      );
    } else {
      const regex = COMBINED_SECRET_REGEX;
      regex.lastIndex = 0;
      
      const parts: React.ReactNode[] = [];
      let lastIndex = 0;
      let match;
      
      while ((match = regex.exec(text)) !== null) {
        const matchText = match[0];
        const matchIndex = match.index;
        
        if (matchIndex > lastIndex) {
          parts.push(text.substring(lastIndex, matchIndex));
        }
        
        parts.push(
          <span key={matchIndex} className="highlight-original-secret">
            {matchText}
          </span>
        );
        
        lastIndex = regex.lastIndex;
      }
      
      if (lastIndex < text.length) {
        parts.push(text.substring(lastIndex));
      }
      
      return parts.length > 0 ? <>{parts}</> : text;
    }
  };

  const originalLines = result ? result.originalContent.split('\n') : [];
  const sanitizedLines = result ? result.sanitizedContent.split('\n') : [];

  return (
    <div className="min-h-screen bg-black text-neutral-100 flex flex-col font-sans relative">
      
      {/* 3D Canvas Background container (restricted to right half on desktop) */}
      <div className="absolute right-0 top-0 w-full md:w-1/2 h-screen z-0 opacity-40 md:opacity-75 pointer-events-none">
        <SecurityMonolith />
      </div>

      {/* Main Content Layout */}
      <div className="relative z-10 w-full max-w-7xl mx-auto px-6 py-8 md:py-16 flex flex-col gap-12 flex-1">
        
        {/* Header */}
        <header className="flex justify-between items-center border-b border-neutral-900 pb-6">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-white" />
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white uppercase">GuardPost</h1>
              <p className="text-xs text-neutral-500 tracking-wider">SECURE REDACTION SYSTEM v2.1</p>
            </div>
          </div>
          <div className="flex items-center gap-2 border border-neutral-800 px-3 py-1.5 text-xs text-neutral-400 font-mono bg-neutral-950/40 backdrop-blur">
            <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse"></span>
            STATELESS ENGINE ACTIVE
          </div>
        </header>

        {/* Dashboard Grid */}
        <main className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          
          {/* Controls Panel */}
          <aside className="lg:col-span-4 flex flex-col gap-6">
            <div className="border border-neutral-850 p-6 bg-neutral-950/40 backdrop-blur-md relative overflow-hidden">
              {/* Corner markings for industrial theme */}
              <div className="absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-neutral-600"></div>
              <div className="absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 border-neutral-600"></div>
              <div className="absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-neutral-600"></div>
              <div className="absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-neutral-600"></div>

              <div className="flex items-center gap-2 text-sm font-semibold text-white tracking-widest uppercase mb-6">
                <Settings size={14} className="text-neutral-400" />
                Detection Filters
              </div>

              <div className="flex flex-col gap-4">
                {Object.entries(settings).map(([key, val]) => (
                  <div key={key} className="flex justify-between items-center py-2.5 border-b border-neutral-900 last:border-0">
                    <div>
                      <span className="text-sm font-medium text-neutral-200 capitalize">
                        {key === 'jwt' ? 'JSON Web Tokens' : key === 'aws' ? 'AWS Credentials' : key === 'database' ? 'Database URIs' : 'Generic Keys'}
                      </span>
                      <p className="text-[10px] text-neutral-500 font-mono uppercase mt-0.5">
                        {key === 'jwt' ? 'standard encodings' : key === 'aws' ? 'access/secret keys' : key === 'database' ? 'postgres/mongo hosts' : 'headers/tokens'}
                      </p>
                    </div>
                    
                    {/* Monochromatic Switch slider */}
                    <button 
                      onClick={() => toggleSetting(key as keyof typeof settings)}
                      className={`w-10 h-5 border flex items-center p-0.5 transition-colors duration-200 cursor-pointer ${val ? 'bg-white border-white' : 'bg-transparent border-neutral-800'}`}
                    >
                      <motion.div 
                        layout 
                        className={`w-3.5 h-3.5 ${val ? 'bg-black' : 'bg-neutral-600'}`}
                        transition={{ type: "spring", stiffness: 700, damping: 30 }}
                      />
                    </button>
                  </div>
                ))}
              </div>

              <div className="mt-8 pt-4 border-t border-neutral-900 flex items-start gap-2.5 text-[10px] text-neutral-500 font-mono uppercase leading-relaxed">
                <Lock size={12} className="text-neutral-600 shrink-0 mt-0.5" />
                <span>Stateless execution: buffer stream is sanitised in-memory and discarded. No write-to-disk logs generated.</span>
              </div>
            </div>
          </aside>

          {/* Workspace Area */}
          <section className="lg:col-span-8 flex flex-col gap-6">
            
            {/* Input card */}
            <div className="border border-neutral-850 bg-neutral-950/40 backdrop-blur-md p-6 flex flex-col gap-6">
              
              {/* Tab Selector */}
              <div className="flex border-b border-neutral-900 pb-px">
                <button 
                  className={`pb-3 px-4 text-xs font-semibold tracking-widest uppercase border-b-2 font-mono transition-all cursor-pointer ${activeTab === 'file' ? 'border-white text-white' : 'border-transparent text-neutral-500 hover:text-neutral-300'}`}
                  onClick={() => { setActiveTab('file'); setError(null); }}
                >
                  [ Artifact File ]
                </button>
                <button 
                  className={`pb-3 px-4 text-xs font-semibold tracking-widest uppercase border-b-2 font-mono transition-all cursor-pointer ${activeTab === 'text' ? 'border-white text-white' : 'border-transparent text-neutral-500 hover:text-neutral-300'}`}
                  onClick={() => { setActiveTab('text'); setError(null); }}
                >
                  [ Raw Text Payload ]
                </button>
              </div>

              <AnimatePresence mode="wait">
                {activeTab === 'file' ? (
                  <motion.div 
                    key="file-tab"
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -5 }}
                    transition={{ duration: 0.15 }}
                    className="flex flex-col"
                  >
                    <div 
                      className={`relative flex flex-col items-center justify-center border border-dashed rounded-md py-12 px-6 transition-all overflow-hidden ${dragActive ? 'border-white bg-neutral-950/80' : 'border-neutral-800 bg-neutral-950/20 hover:border-neutral-700'}`}
                      onDragEnter={handleDrag}
                      onDragOver={handleDrag}
                      onDragLeave={handleDrag}
                      onDrop={handleDrop}
                    >
                      <input 
                        type="file" 
                        ref={fileInputRef} 
                        onChange={handleFileChange}
                        accept=".txt,.json,.har" 
                        className="absolute inset-0 opacity-0 cursor-pointer z-10"
                      />
                      
                      {/* Laser scanner element (pure white horizontal beam scanning) */}
                      {loading && <div className="laser-scanner"></div>}

                      {selectedFile ? (
                        <div className="flex flex-col items-center text-center z-20">
                          <FileJson className="w-10 h-10 text-neutral-400 mb-3" />
                          <span className="text-sm font-semibold text-white tracking-wide">{selectedFile.name}</span>
                          <span className="text-[10px] text-neutral-500 font-mono mt-1">{(selectedFile.size / 1024).toFixed(2)} KB</span>
                          <button 
                            onClick={(e) => { e.stopPropagation(); clearFile(); }}
                            className="mt-4 flex items-center gap-1.5 text-xs text-neutral-400 hover:text-white border border-neutral-800 px-3 py-1 hover:bg-neutral-900 transition-all font-mono uppercase cursor-pointer"
                          >
                            <Trash2 size={12} /> Clear Artifact
                          </button>
                        </div>
                      ) : (
                        <div className="flex flex-col items-center text-center z-0 pointer-events-none">
                          <UploadCloud className="w-10 h-10 text-neutral-600 mb-4" />
                          <p className="text-sm font-medium text-neutral-300">Drag and drop security logs or configuration files here</p>
                          <span className="text-xs text-neutral-500 mt-2 font-mono uppercase">SUPPORTS TXT, JSON, HAR UP TO 50MB</span>
                        </div>
                      )}
                    </div>
                  </motion.div>
                ) : (
                  <motion.div 
                    key="text-tab"
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -5 }}
                    transition={{ duration: 0.15 }}
                    className="flex flex-col"
                  >
                    <textarea 
                      className="w-full h-64 bg-neutral-950 border border-neutral-800 rounded-md p-4 text-neutral-300 font-mono text-xs focus:border-neutral-500 outline-none transition-colors placeholder:text-neutral-600 resize-y"
                      value={rawText}
                      onChange={(e) => setRawText(e.target.value)}
                      placeholder="Paste payload text or raw parameters containing sensitive entries..."
                    ></textarea>
                  </motion.div>
                )}
              </AnimatePresence>

              {error && (
                <div className="flex items-center gap-2 text-xs text-red-500 font-mono uppercase">
                  <AlertCircle size={14} />
                  <span>{error}</span>
                </div>
              )}

              <button 
                onClick={handleSanitize}
                disabled={loading || (activeTab === 'file' && !selectedFile) || (activeTab === 'text' && !rawText.trim())}
                className="bg-white text-black font-semibold text-xs tracking-widest uppercase py-3.5 px-6 hover:bg-neutral-200 transition-colors disabled:opacity-30 disabled:pointer-events-none flex items-center justify-center gap-2 self-start cursor-pointer border border-white"
              >
                {loading ? (
                  <>
                    <span className="w-1.5 h-1.5 rounded-full bg-black animate-ping"></span>
                    PROCESSING PAYLOAD...
                  </>
                ) : (
                  <>
                    <Shield size={14} />
                    SANITIZE PAYLOAD
                  </>
                )}
              </button>
            </div>

            {/* Results Animation wrapper */}
            <AnimatePresence>
              {result && (
                <motion.div 
                  initial={{ opacity: 0, y: 15 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: 15 }}
                  className="flex flex-col gap-6"
                >
                  {/* Results Count Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {[
                      { title: 'JWTs REDACTED', val: result.stats.jwt },
                      { title: 'AWS CREDENTIALS', val: result.stats.aws },
                      { title: 'DATABASE URIS', val: result.stats.database },
                      { title: 'GENERIC KEYS', val: result.stats.generic }
                    ].map((stat, idx) => (
                      <div key={idx} className="border border-neutral-850 bg-neutral-950/40 p-4 font-mono">
                        <span className="text-[10px] text-neutral-500 block">{stat.title}</span>
                        <span className="text-xl font-bold text-white block mt-1">{stat.val}</span>
                      </div>
                    ))}
                  </div>

                  {/* Diff Viewer panel */}
                  <div className="border border-neutral-850 bg-neutral-950/40 p-6 flex flex-col gap-4">
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-2 text-xs font-semibold text-white tracking-widest uppercase">
                        <ShieldAlert size={14} className="text-neutral-400" />
                        Comparison Workspace
                      </div>
                      <button 
                        onClick={handleCopy}
                        className="flex items-center gap-1.5 text-xs text-neutral-400 hover:text-white border border-neutral-800 px-3 py-1.5 hover:bg-neutral-900 transition-all font-mono uppercase cursor-pointer"
                      >
                        {copied ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
                        {copied ? 'Copied' : 'Copy Sanitised output'}
                      </button>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 border border-neutral-850 bg-black overflow-hidden h-[420px]">
                      
                      {/* Original Block */}
                      <div className="flex flex-col border-b md:border-b-0 md:border-r border-neutral-900">
                        <div className="bg-neutral-950 border-b border-neutral-900 py-2 px-4 text-[10px] font-mono text-neutral-500 uppercase flex justify-between">
                          Original Payload
                          {result.fileName && <span className="text-neutral-600">{result.fileName}</span>}
                        </div>
                        <div 
                          ref={leftScrollRef}
                          onScroll={handleLeftScroll}
                          className="flex-1 overflow-auto p-4 font-mono text-[11px] leading-relaxed text-neutral-400"
                        >
                          {originalLines.map((line, idx) => (
                            <div className="flex select-text" key={idx}>
                              <span className="w-8 text-neutral-700 text-right pr-3 select-none">{idx + 1}</span>
                              <span className="flex-1 break-all whitespace-pre-wrap">{renderHighlightedText(line, false)}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Sanitised Block */}
                      <div className="flex flex-col">
                        <div className="bg-neutral-950 border-b border-neutral-900 py-2 px-4 text-[10px] font-mono text-neutral-500 uppercase flex justify-between">
                          Sanitised Output
                          <span className="text-neutral-400 flex items-center gap-1"><Lock size={9} /> SECURE</span>
                        </div>
                        <div 
                          ref={rightScrollRef}
                          onScroll={handleRightScroll}
                          className="flex-1 overflow-auto p-4 font-mono text-[11px] leading-relaxed text-neutral-300"
                        >
                          {sanitizedLines.map((line, idx) => (
                            <div className="flex select-text" key={idx}>
                              <span className="w-8 text-neutral-700 text-right pr-3 select-none">{idx + 1}</span>
                              <span className="flex-1 break-all whitespace-pre-wrap">{renderHighlightedText(line, true)}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                    </div>
                  </div>

                  {/* Redacted logs list */}
                  {result.details && result.details.length > 0 && (
                    <div className="border border-neutral-850 bg-neutral-950/40 p-6 flex flex-col gap-4">
                      <div className="text-xs font-semibold text-white tracking-widest uppercase">
                        Redaction Signatures Log
                      </div>
                      <div className="flex flex-col gap-2 max-h-48 overflow-y-auto pr-2">
                        {result.details.map((detail, idx) => (
                          <div key={idx} className="flex justify-between items-center border border-neutral-900 p-2.5 font-mono text-[11px]">
                            <div className="flex items-center gap-3">
                              <span className="text-[9px] font-bold border border-neutral-800 text-neutral-400 px-1.5 py-0.5 rounded uppercase">
                                {detail.type}
                              </span>
                              <span className="text-neutral-500">{detail.originalSnippet}</span>
                            </div>
                            <div className="flex items-center gap-2 text-neutral-500">
                              <ChevronRight size={12} />
                              <span className="text-white font-semibold">{detail.placeholder}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                </motion.div>
              )}
            </AnimatePresence>

          </section>
        </main>
      </div>
    </div>
  );
}
