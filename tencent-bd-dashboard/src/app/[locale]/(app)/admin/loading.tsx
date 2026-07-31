import { SkeletonPage, SkeletonRows } from '@/components/Skeleton';

export default function AdminLoading() {
  return (
    <SkeletonPage>
      <SkeletonRows count={8} />
    </SkeletonPage>
  );
}
