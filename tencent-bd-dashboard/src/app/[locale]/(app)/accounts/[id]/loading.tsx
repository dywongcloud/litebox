import { SkeletonPage, SkeletonRows } from '@/components/Skeleton';

export default function AccountResearchLoading() {
  return (
    <SkeletonPage>
      <SkeletonRows count={6} />
    </SkeletonPage>
  );
}
