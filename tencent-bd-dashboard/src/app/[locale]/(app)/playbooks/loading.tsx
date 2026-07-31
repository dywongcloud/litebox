import { SkeletonCards, SkeletonPage } from '@/components/Skeleton';

export default function PlaybooksLoading() {
  return (
    <SkeletonPage>
      <SkeletonCards count={6} />
    </SkeletonPage>
  );
}
