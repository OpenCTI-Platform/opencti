import React from 'react';
import { Alert } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { huntDetailsStatusMutation } from './HuntDetails';
import { hasHuntLogic, isAutonomousHunt, isHuntPendingReview } from './hunt-utils';
import { notifyPayloadErrors } from './hunt-mutation-utils';
import { HuntDetailsStatusMutation } from './__generated__/HuntDetailsStatusMutation.graphql';

interface HuntDraftBannerProps {
  hunt: {
    id: string;
    hunt_source_kind: string;
    hunt_status: string;
    hunt_type: string;
    hunt_schedule: string;
    hunt_pir_activation?: boolean | null;
    sigma_rule?: string | null;
    native_queries?: ReadonlyArray<{ platform: string }> | null;
  };
}

/** Draft-first: hunts written by an agent or imported from XTM Hub wait for an analyst before they run. */
const HuntDraftBanner = ({ hunt }: HuntDraftBannerProps) => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const isEnterpriseEdition = useEnterpriseEdition();
  const [commit, activating] = useApiMutation<HuntDetailsStatusMutation>(huntDetailsStatusMutation);
  const pendingReview = isHuntPendingReview(hunt);
  if (!pendingReview && !draftContext) {
    return null;
  }
  const remaining: string[] = [];
  if (pendingReview) {
    remaining.push(hunt.hunt_source_kind === 'agent'
      ? t_i18n('Review the hypothesis and the logic the agent proposed')
      : t_i18n('Review the scope and the logic imported from XTM Hub'));
    if (!hasHuntLogic(hunt)) {
      remaining.push(t_i18n('Add a Sigma rule or a native query in the Logic tab'));
    }
    if (!isEnterpriseEdition && isAutonomousHunt(hunt)) {
      remaining.push(t_i18n('Switch the schedule to manual, or enable the Enterprise Edition to run it autonomously'));
    }
  }
  if (draftContext) {
    remaining.push(t_i18n('Validate the draft workspace: the hunt does not run before'));
  }
  const canActivate = pendingReview && !draftContext && hasHuntLogic(hunt) && (isEnterpriseEdition || !isAutonomousHunt(hunt));
  const activate = () => {
    commit({
      variables: { id: hunt.id, input: [{ key: 'hunt_status', value: ['active'] }] },
      onCompleted: (_, errors) => {
        notifyPayloadErrors(errors);
      },
    });
  };
  return (
    <div data-testid="hunt-draft-banner" style={{ marginBottom: 16 }}>
      <Alert
        severity="info"
        title={pendingReview ? t_i18n('This hunt is a draft') : t_i18n('You are in a draft workspace')}
        description={(
          <ul style={{ margin: 0, paddingLeft: 20 }} data-testid="hunt-draft-banner-remaining">
            {remaining.map((item) => <li key={item}>{item}</li>)}
          </ul>
        )}
        action={canActivate ? (
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <Button variant="secondary" size="small" onClick={activate} disabled={activating} data-testid="hunt-draft-banner-activate">
              {t_i18n('Activate the hunt')}
            </Button>
          </Security>
        ) : undefined}
      />
    </div>
  );
};

export default HuntDraftBanner;
