import React from 'react';
import { Link } from 'react-router';
import { Alert } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { huntDraftWorkspacePath, isHuntPendingReview } from './hunt-utils';

interface HuntDraftBannerProps {
  hunt: {
    id: string;
    hunt_source_kind: string;
    hunt_status: string;
  };
}

/**
 * Draft-first: hunts written by an agent or imported from XTM Hub wait for an analyst before they run. What the hunt
 * still needs and its activation are in the status header of the page.
 */
const HuntDraftBanner = ({ hunt }: HuntDraftBannerProps) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const pendingReview = isHuntPendingReview(hunt);
  if (!pendingReview && !draftContext) {
    return null;
  }
  const remaining: string[] = [];
  if (pendingReview) {
    remaining.push(hunt.hunt_source_kind === 'agent'
      ? t_i18n('Review the hypothesis and the logic the agent proposed')
      : t_i18n('Review the scope and the logic imported from XTM Hub'));
    remaining.push(t_i18n('Activate it from the status bar above once every item of its checklist is ready'));
  }
  if (draftContext) {
    remaining.push(t_i18n('Validate the draft workspace: the hunt does not run before'));
  }
  return (
    <div data-testid="hunt-draft-banner" style={{ marginBottom: 16 }}>
      <Alert
        severity="info"
        title={pendingReview ? t_i18n('This hunt is a draft') : t_i18n('You are in a draft workspace')}
        // The description is a paragraph: the list is built from phrasing content
        description={(
          <span role="list" data-testid="hunt-draft-banner-remaining">
            {remaining.map((item) => <span role="listitem" key={item} style={{ display: 'list-item', marginLeft: 20 }}>{item}</span>)}
          </span>
        )}
        action={draftContext ? (
          <Button variant="secondary" size="small" component={Link} to={huntDraftWorkspacePath(draftContext.id)} data-testid="hunt-draft-banner-open-draft">
            {t_i18n('Open the draft')}
          </Button>
        ) : undefined}
      />
    </div>
  );
};

export default HuntDraftBanner;
