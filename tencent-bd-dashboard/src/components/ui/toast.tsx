'use client';

import * as ToastPrimitive from '@radix-ui/react-toast';
import { AlertTriangle, CheckCircle2, Info, X } from 'lucide-react';
import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';

import { cn } from '@/lib/utils';

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

const TONE_ICON = {
  info: Info,
  success: CheckCircle2,
  error: AlertTriangle,
} as const;

const TONE_ACCENT: Record<ToastTone, string> = {
  info: 'text-[var(--brand-400)]',
  success: 'text-[var(--success)]',
  error: 'text-[var(--danger)]',
};

/**
 * Toast host, backed by Radix.
 *
 * The public surface is unchanged from the hand-rolled version this replaces
 * (`useToast().show(message, tone)`), so no call site moved -- what changed is
 * underneath: Radix gives these a live region that announces correctly, a
 * swipe-to-dismiss gesture, hover/focus pausing of the dismiss timer, and
 * `F8` focus traversal into the toast stack. The previous implementation
 * dismissed on a bare `setTimeout` that kept running while the pointer was
 * over the toast, so a message could vanish mid-read.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const show = useCallback((message: string, tone: ToastTone = 'info') => {
    setItems((current) => [...current, { id: nextId.current++, tone, message }]);
  }, []);

  const dismiss = useCallback((id: number) => {
    setItems((current) => current.filter((item) => item.id !== id));
  }, []);

  const value = useMemo(() => ({ show }), [show]);

  return (
    <ToastContext.Provider value={value}>
      <ToastPrimitive.Provider swipeDirection="right" duration={AUTO_DISMISS_MS}>
        {children}

        {items.map((item) => {
          const Icon = TONE_ICON[item.tone];
          return (
            <ToastPrimitive.Root
              key={item.id}
              data-slot="toast"
              onOpenChange={(open) => {
                if (!open) dismiss(item.id);
              }}
              className={cn(
                'group pointer-events-auto flex items-start gap-3 rounded-[var(--radius-md)] p-3 pr-2.5',
                'border border-[var(--glass-border)] bg-[var(--glass-bg-strong)] backdrop-blur-[22px]',
                'shadow-[var(--glass-shadow)]',
                'data-[state=open]:animate-in data-[state=open]:slide-in-from-right-full data-[state=open]:fade-in-0',
                'data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=closed]:zoom-out-95',
                'data-[swipe=move]:translate-x-[var(--radix-toast-swipe-move-x)] data-[swipe=move]:transition-none',
                'data-[swipe=cancel]:translate-x-0 data-[swipe=cancel]:transition-transform',
                'data-[swipe=end]:animate-out data-[swipe=end]:slide-out-to-right-full',
              )}
            >
              <Icon className={cn('mt-px size-4 shrink-0', TONE_ACCENT[item.tone])} />
              <ToastPrimitive.Description className="flex-1 text-[13px] leading-snug text-[var(--ink)]">
                {item.message}
              </ToastPrimitive.Description>
              <ToastPrimitive.Close
                aria-label="Dismiss"
                className={cn(
                  'grid size-6 shrink-0 place-items-center rounded-[var(--radius-sm)]',
                  'text-[var(--muted)] transition-colors hover:bg-[var(--bg-subtle)] hover:text-[var(--ink)]',
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--focus-ring)]/55',
                )}
              >
                <X className="size-3.5" />
              </ToastPrimitive.Close>
            </ToastPrimitive.Root>
          );
        })}

        <ToastPrimitive.Viewport
          className={cn(
            'fixed bottom-5 right-5 z-[90] flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2',
            'outline-none max-[500px]:inset-x-3 max-[500px]:bottom-3 max-[500px]:w-auto',
          )}
        />
      </ToastPrimitive.Provider>
    </ToastContext.Provider>
  );
}

/**
 * Falls back to a console warning rather than throwing when no provider is
 * mounted: a missing toast is a degraded notification, not a reason to take
 * down the surrounding page.
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
