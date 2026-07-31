import { SkeletonBoard, SkeletonPage } from '@/components/Skeleton';

export default function BoardLoading() {
  return (
    <SkeletonPage>
      <SkeletonBoard />
    </SkeletonPage>
  );
}
