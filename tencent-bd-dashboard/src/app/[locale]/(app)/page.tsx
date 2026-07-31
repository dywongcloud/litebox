import { redirect } from '@/i18n/navigation';

/** The dashboard's root path has no content of its own; the catalog is home. */
export default async function DashboardRoot({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  redirect({ href: '/products', locale });
}
