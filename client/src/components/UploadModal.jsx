import React, { useState, useRef } from 'react';
import { UploadCloud, File, AlertCircle, CheckCircle2, Lock, Cpu, CloudUpload, X } from 'lucide-react';
import { Modal } from './ui/Modal';
import { Button } from './ui/Button';
import { Input } from './ui/Input';
import { Label } from './ui/Label';
import { Alert, AlertDescription } from './ui/Alert';
import { uploadDocument } from '../api/documents';

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

const CATEGORIES = [
  'General',
  'Financial',
  'Legal',
  'Identity',
  'Healthcare',
  'Confidential'
];

export function UploadModal({ isOpen, onClose, onUploadSuccess }) {
  const [file, setFile] = useState(null);
  const [title, setTitle] = useState('');
  const [category, setCategory] = useState('General');
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState(null);
  const [step, setStep] = useState('idle'); // 'idle' | 'encrypting' | 'uploading' | 'success'
  const fileInputRef = useRef(null);

  const resetForm = () => {
    setFile(null);
    setTitle('');
    setCategory('General');
    setError(null);
    setStep('idle');
    setIsDragging(false);
  };

  const handleClose = () => {
    if (step === 'encrypting' || step === 'uploading') return;
    resetForm();
    onClose();
  };

  const validateAndSetFile = (selectedFile) => {
    setError(null);
    if (!selectedFile) return;

    if (selectedFile.size > MAX_FILE_SIZE) {
      setError(`File size exceeds the 10MB perimeter limit (${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB).`);
      return;
    }

    setFile(selectedFile);
    if (!title.trim()) {
      // Auto-populate title without extension
      const nameWithoutExt = selectedFile.name.replace(/\.[^/.]+$/, '');
      setTitle(nameWithoutExt);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file to encrypt and store.');
      return;
    }

    try {
      setError(null);
      // Simulate/Show crypto processing pipeline
      setStep('encrypting');
      await new Promise((r) => setTimeout(r, 450));

      setStep('uploading');
      const formData = new FormData();
      formData.append('document', file);
      formData.append('title', title.trim() || file.name);
      formData.append('category', category);

      const createdDoc = await uploadDocument(formData);
      setStep('success');

      setTimeout(() => {
        if (onUploadSuccess) onUploadSuccess(createdDoc);
        handleClose();
      }, 700);
    } catch (err) {
      setStep('idle');
      setError(err.message || 'Failed to upload document.');
    }
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={handleClose}
      title="Secure Vault Ingestion"
      description="Zero-Trust upload: documents are envelope-encrypted with AES-256-GCM in volatile RAM."
      maxWidth="max-w-lg"
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Drag & Drop Area */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`relative border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-all ${
            isDragging
              ? 'border-indigo-500 bg-indigo-950/30'
              : file
              ? 'border-emerald-500/60 bg-emerald-950/20'
              : 'border-slate-800 hover:border-slate-700 bg-slate-950/50'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            onChange={(e) => validateAndSetFile(e.target.files?.[0])}
            className="hidden"
          />

          {file ? (
            <div className="flex items-center justify-between gap-3 text-left">
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-10 h-10 rounded-lg bg-emerald-500/20 border border-emerald-500/40 text-emerald-400 flex items-center justify-center shrink-0">
                  <File className="w-5 h-5" />
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-slate-100 truncate">{file.name}</p>
                  <p className="text-xs text-slate-400">{formatFileSize(file.size)}</p>
                </div>
              </div>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  setFile(null);
                }}
                className="p-1 rounded-md text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors"
                title="Remove file"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <div className="flex flex-col items-center">
              <div className="w-12 h-12 rounded-xl bg-slate-800/80 border border-slate-700/60 flex items-center justify-center text-indigo-400 mb-3 shadow-inner">
                <UploadCloud className="w-6 h-6" />
              </div>
              <p className="text-sm font-semibold text-slate-200">
                Click to browse or drag & drop file
              </p>
              <p className="text-xs text-slate-400 mt-1">
                Supports all formats up to 10MB (RAM encrypted)
              </p>
            </div>
          )}
        </div>

        {/* Title Input */}
        <div>
          <Label htmlFor="doc-title">Document Title</Label>
          <Input
            id="doc-title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="e.g. Q4 Financial Audit Report"
            disabled={step !== 'idle'}
          />
        </div>

        {/* Category Selection */}
        <div>
          <Label htmlFor="doc-category">Security Classification</Label>
          <select
            id="doc-category"
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            disabled={step !== 'idle'}
            className="w-full h-10 px-3 rounded-lg bg-slate-900 border border-slate-800 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 transition-all"
          >
            {CATEGORIES.map((cat) => (
              <option key={cat} value={cat} className="bg-slate-900 text-slate-200">
                {cat}
              </option>
            ))}
          </select>
        </div>

        {/* Live Encryption Pipeline Status */}
        {step !== 'idle' && (
          <div className="p-3 rounded-xl bg-slate-950 border border-slate-800/80 space-y-2">
            <div className="flex items-center gap-2 text-xs font-semibold">
              {step === 'encrypting' && (
                <>
                  <Cpu className="w-4 h-4 text-amber-400 animate-spin" />
                  <span className="text-amber-400">Encrypting buffer in RAM (AES-256-GCM + IV)...</span>
                </>
              )}
              {step === 'uploading' && (
                <>
                  <CloudUpload className="w-4 h-4 text-indigo-400 animate-bounce" />
                  <span className="text-indigo-400">Uploading ciphertext stream to private storage...</span>
                </>
              )}
              {step === 'success' && (
                <>
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span className="text-emerald-400">Encrypted and cataloged successfully!</span>
                </>
              )}
            </div>
            <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-300 ${
                  step === 'encrypting'
                    ? 'w-1/2 bg-amber-500'
                    : step === 'uploading'
                    ? 'w-4/5 bg-indigo-500'
                    : 'w-full bg-emerald-500'
                }`}
              />
            </div>
          </div>
        )}

        {/* Footer Actions */}
        <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800/60">
          <Button
            type="button"
            variant="ghost"
            onClick={handleClose}
            disabled={step !== 'idle'}
          >
            Cancel
          </Button>
          <Button
            type="submit"
            variant="emerald"
            disabled={!file || step !== 'idle'}
            className="gap-2"
          >
            <Lock className="w-3.5 h-3.5" />
            {step === 'idle' ? 'Encrypt & Upload' : 'Processing...'}
          </Button>
        </div>
      </form>
    </Modal>
  );
}

export default UploadModal;
