'use client';

import { useActionState, useEffect, useState } from 'react';
import { useTranslations } from 'next-intl';

import type { Motion } from '@/db/schema';
import { CSRF_FIELD } from '@/lib/security/csrf-constants';
import { ConfirmButton } from '@/components/ConfirmButton';
import { Modal } from '@/components/Modal';
import { TextAreaField, TextField } from '@/components/fields';
import { SubmitButton } from '@/components/SubmitButton';
import { removeMotion, saveMotion } from '@/server/actions/board';
import type { FormActionState } from '@/server/actions/shared';

const initialState: FormActionState = {};

export function PlaybooksClient({ items, canWrite, csrfToken }: { items: Motion[]; canWrite: boolean; csrfToken: string }) {
  const t = useTranslations('playbooks');
  const tCommon = useTranslations('common');
  const [modal, setModal] = useState<{ type: 'create' } | { type: 'edit'; motion: Motion } | null>(null);

  return (
    <>
      <div className="row" style={{ marginBottom: 12 }}>
        {canWrite ? (
          <button type="button" className="primary" onClick={() => setModal({ type: 'create' })}>
            {t('addMotion')}
          </button>
        ) : null}
      </div>

      <div className="grid-3">
        {items.map((motion) => (
          <div className="card motion-card" key={motion.id}>
            <h3>{motion.opportunity}</h3>
            <p>
              <b>{t('fieldTriggerSignals')}:</b> {motion.triggerSignals || '-'}
            </p>
            <p>
              <b>{t('fieldIcp')}:</b> {motion.icp || '-'}
            </p>
            <p>
              <b>{t('fieldWedgeProduct')}:</b> {motion.wedgeProduct || '-'}
            </p>
            {canWrite ? (
              <div className="row" style={{ marginTop: 10 }}>
                <button type="button" onClick={() => setModal({ type: 'edit', motion })}>
                  {tCommon('edit')}
                </button>
                <form
                  action={async (formData) => {
                    await removeMotion(formData);
                  }}
                >
                  <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
                  <input type="hidden" name="id" value={motion.id} />
                  <ConfirmButton label={tCommon('delete')} />
                </form>
              </div>
            ) : null}
          </div>
        ))}
        {items.length === 0 ? <p className="empty-state">{tCommon('emptyState')}</p> : null}
      </div>

      {modal ? (
        <MotionFormModal motion={modal.type === 'edit' ? modal.motion : undefined} csrfToken={csrfToken} onClose={() => setModal(null)} />
      ) : null}
    </>
  );
}

function MotionFormModal({ motion, csrfToken, onClose }: { motion?: Motion; csrfToken: string; onClose: () => void }) {
  const t = useTranslations('playbooks');
  const tCommon = useTranslations('common');
  const [state, formAction] = useActionState(saveMotion, initialState);

  useEffect(() => {
    if (state.success) onClose();
  }, [state.success, onClose]);

  return (
    <Modal title={motion ? t('editTitle') : t('createTitle')} onClose={onClose}>
      <div className="modal-header">
        <div>
          <h2 style={{ margin: 0 }}>{motion ? t('editTitle') : t('createTitle')}</h2>
          <p className="small">{t('subtitle')}</p>
        </div>
        <button type="button" onClick={onClose}>
          {tCommon('close')}
        </button>
      </div>

      {state.message ? (
        <p className="form-message" data-tone="error" role="alert">
          {state.message}
        </p>
      ) : null}

      <form action={formAction} id="motion-form">
        <input type="hidden" name={CSRF_FIELD} value={csrfToken} />
        {motion ? <input type="hidden" name="id" value={motion.id} /> : null}

        <div className="form-grid">
          <TextField className="full" label={t('fieldOpportunity')} name="opportunity" defaultValue={motion?.opportunity} errors={state.errors} required />
          <TextAreaField label={t('fieldTriggerSignals')} name="triggerSignals" defaultValue={motion?.triggerSignals} />
          <TextAreaField label={t('fieldIcp')} name="icp" defaultValue={motion?.icp} />
          <TextAreaField label={t('fieldDiscoveryQuestions')} name="discoveryQuestions" defaultValue={motion?.discoveryQuestions} />
          <TextAreaField label={t('fieldWedgeProduct')} name="wedgeProduct" defaultValue={motion?.wedgeProduct} />
          <TextAreaField label={t('fieldPocStrategy')} name="pocStrategy" defaultValue={motion?.pocStrategy} />
          <TextAreaField label={t('fieldSuccessMetrics')} name="successMetrics" defaultValue={motion?.successMetrics} />
          <TextAreaField label={t('fieldExpansionPath')} name="expansionPath" defaultValue={motion?.expansionPath} />
          <TextAreaField label={t('fieldRisks')} name="risks" defaultValue={motion?.risks} />
          <TextAreaField label={t('fieldEvidenceRequired')} name="evidenceRequired" defaultValue={motion?.evidenceRequired} />
        </div>
      </form>

      <div className="modal-footer">
        <button type="button" onClick={onClose}>
          {tCommon('cancel')}
        </button>
        <SubmitButton form="motion-form" className="primary" pendingLabel={tCommon('saving')}>
          {tCommon('save')}
        </SubmitButton>
      </div>
    </Modal>
  );
}
