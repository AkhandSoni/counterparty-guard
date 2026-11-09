import type React from 'react';
import { useState } from 'react';
import { CheckIcon, CopyIcon, TerminalIcon } from './Icons';

interface CodeBlockProps {
  code: string;
  language?: string;
  title?: string;
}

export const CodeBlock: React.FC<CodeBlockProps> = ({ code, title = 'Terminal Command' }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="rounded-lg border border-slate-700 bg-slate-900/90 overflow-hidden font-mono text-xs">
      <div className="flex items-center justify-between px-3 py-2 bg-slate-800/80 border-b border-slate-700">
        <div className="flex items-center gap-2 text-slate-300">
          <TerminalIcon size={14} className="text-cyan-400" />
          <span className="font-semibold text-[11px] tracking-wide uppercase">{title}</span>
        </div>
        <button
          type="button"
          onClick={handleCopy}
          className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-700 hover:bg-slate-600 text-slate-200 transition"
        >
          {copied ? (
            <>
              <CheckIcon size={12} className="text-emerald-400" />
              <span className="text-[10px] text-emerald-400">Copied!</span>
            </>
          ) : (
            <>
              <CopyIcon size={12} />
              <span className="text-[10px]">Copy</span>
            </>
          )}
        </button>
      </div>
      <pre className="p-3 overflow-x-auto text-cyan-300 leading-relaxed whitespace-pre-wrap break-all">
        {code}
      </pre>
    </div>
  );
};
