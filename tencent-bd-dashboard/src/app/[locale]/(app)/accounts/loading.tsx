import { SkeletonPage, SkeletonRows } from '@/components/Skeleton';

export default function AccountsLoading() {
  return (
    <SkeletonPage>
      <SkeletonRows count={10} />
    </SkeletonPage>
  );
}
