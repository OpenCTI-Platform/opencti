import React from 'react';
import Alert from '../../../components/Alert';
import { useFormatter } from '../../../components/i18n';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { isHuntPendingReview } from './hunt-utils';

interface HuntDraftBannerProps {
  hunt: { hunt_source_kind: string; hunt_status: string };
}

/** Draft-first: hunts written by an agent or imported from XTM Hub wait for an analyst before they run. */
const HuntDraftBanner = ({ hunt }: HuntDraftBannerProps) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const messages: string[] = [];
  if (isHuntPendingReview(hunt)) {
    messages.push(hunt.hunt_source_kind === 'agent'
      ? t_i18n('This hunt was proposed by an agent. Review its hypothesis and logic, then activate it.')
      : t_i18n('This hunt was imported from XTM Hub. Review its scope and logic, then activate it.'));
  }
  if (draftContext) {
    messages.push(t_i18n('You are in a draft workspace: this hunt does not run until the draft is validated.'));
  }
  if (messages.length === 0) {
    return null;
  }
  return (
    <div data-testid="hunt-draft-banner" style={{ marginBottom: 16 }}>
      <Alert severity="info" content={messages.join(' ')} />
    </div>
  );
};

export default HuntDraftBanner;
