import { getTranslations } from 'next-intl/server';

export default async function LocaleNotFound() {
  const t = await getTranslations('errors');

  return (
    <div className="empty-state" style={{ minHeight: '60dvh', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
      <h1 style={{ margin: '0 0 8px' }}>{t('pageNotFound')}</h1>
      <p>{t('pageNotFoundBody')}</p>
    </div>
  );
}
