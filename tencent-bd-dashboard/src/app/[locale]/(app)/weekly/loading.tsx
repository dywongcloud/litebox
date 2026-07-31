import { SkeletonCards, SkeletonPage } from '@/components/Skeleton';

export default function WeeklyLoading() {
  return (
    <SkeletonPage>
      <SkeletonCards count={9} />
    </SkeletonPage>
  );
}
