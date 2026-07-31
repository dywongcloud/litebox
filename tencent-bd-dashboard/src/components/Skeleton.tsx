/**
 * Loading-state building blocks for route `loading.tsx` files.
 *
 * Server component (no `'use client'`): a `loading.tsx` renders while the
 * page segment it guards is still resolving, so this never needs interactivity
 * -- just markup that echoes the shape of what is about to arrive, to avoid
 * the blank-then-pop layout shift a bare spinner causes.
 */
export function SkeletonKpis({ count = 6 }: { count?: number }) {
  return (
    <div className="kpis" aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="skeleton skeleton-kpi" />
      ))}
    </div>
  );
}

export function SkeletonRows({ count = 8 }: { count?: number }) {
  return (
    <div className="stack" aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="skeleton skeleton-row" />
      ))}
    </div>
  );
}

export function SkeletonCards({ count = 6 }: { count?: number }) {
  return (
    <div className="grid-3" aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="skeleton skeleton-card" />
      ))}
    </div>
  );
}

export function SkeletonBoard() {
  return (
    <div className="board" aria-hidden="true">
      {Array.from({ length: 4 }, (_, col) => (
        <div className="board-col" key={col}>
          <div className="skeleton skeleton-text" style={{ width: '50%', marginBottom: 'var(--space-3)' }} />
          {Array.from({ length: col === 0 ? 3 : 2 }, (_, row) => (
            <div key={row} className="skeleton skeleton-card" style={{ height: 90, marginBottom: 'var(--space-2)' }} />
          ))}
        </div>
      ))}
    </div>
  );
}

/**
 * Page-level wrapper: an accessible "loading" announcement plus a title bar
 * skeleton, so every route's `loading.tsx` starts from the same shell.
 */
export function SkeletonPage({ children }: { children: React.ReactNode }) {
  return (
    <div role="status" aria-label="Loading">
      <div className="skeleton skeleton-title" />
      {children}
    </div>
  );
}
