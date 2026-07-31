import { SkeletonCards, SkeletonRows } from '@/components/Skeleton';

export default function SopLoading() {
  return (
    <div className="stack" role="status" aria-label="Loading">
      <SkeletonCards count={6} />
      <SkeletonRows count={6} />
    </div>
  );
}
