'use client';

import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';

/**
 * Global toast notifications.
 *
 * Replaces `window.alert` for action feedback: a native alert is a blocking,
 * unstyled, unthemed browser dialog that halts the whole page -- wrong for a
 * dashboard where a rep is mid-flow. This is a plain React context rather
 * than a dependency: three states (info/success/error), auto-dismiss, and an
 * ARIA live region cover everything this app needs.
 */

export type ToastTone = 'info' | 'success' | 'error';

interface ToastItem {
  id: number;
  tone: ToastTone;
  message: string;
}

interface ToastContextValue {
  show: (message: string, tone?: ToastTone) => void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const AUTO_DISMISS_MS = 5000;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const show = useCallback((message: string, tone: ToastTone = 'info') => {
    const id = nextId.current++;
    setItems((current) => [...current, { id, tone, message }]);
    setTimeout(() => {
      setItems((current) => current.filter((item) => item.id !== id));
    }, AUTO_DISMISS_MS);
  }, []);

  const dismiss = useCallback((id: number) => {
    setItems((current) => current.filter((item) => item.id !== id));
  }, []);

  const value = useMemo(() => ({ show }), [show]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-region" role="region" aria-label="Notifications">
        {items.map((item) => (
          <div key={item.id} className="toast" data-tone={item.tone} role="status">
            <span>{item.message}</span>
            <button type="button" className="toast-close" onClick={() => dismiss(item.id)} aria-label="Dismiss">
              x
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

/**
 * Returns a stable `show` function. Falls back to a no-op with a console
 * warning rather than throwing when rendered outside the provider -- a
 * missing toast is a degraded experience, not a reason to crash the page
 * that was trying to report a real error to the user.
 */
export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) {
    return {
      show: (message) => console.warn('[toast] ToastProvider missing; message dropped:', message),
    };
  }
  return ctx;
}
