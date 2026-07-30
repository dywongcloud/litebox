import { getTranslations } from 'next-intl/server';

import { CsrfField } from '@/components/CsrfField';
import { logout } from '@/server/actions/auth';

export async function SignOutForm() {
  const t = await getTranslations('app');

  return (
    <form action={logout}>
      <CsrfField />
      <button type="submit">{t('signOut')}</button>
    </form>
  );
}
