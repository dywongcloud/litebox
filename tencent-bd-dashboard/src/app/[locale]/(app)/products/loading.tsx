import { SkeletonKpis, SkeletonPage, SkeletonRows } from '@/components/Skeleton';

export default function ProductsLoading() {
  return (
    <SkeletonPage>
      <SkeletonKpis count={6} />
      <SkeletonRows count={10} />
    </SkeletonPage>
  );
}
