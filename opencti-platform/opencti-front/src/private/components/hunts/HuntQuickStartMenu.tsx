import React, { useState } from 'react';
import { AutoAwesomeOutlined, CloudDownloadOutlined, PolicyOutlined, RuleOutlined } from '@mui/icons-material';
import { Menu, MenuContent, MenuItem, MenuTrigger, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../components/i18n';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import HuntGuidedCreation, { type HuntGuidedKind } from './HuntGuidedCreation';
import HuntPlanDialog from './HuntPlanDialog';
import { useHuntPackHubUrl } from './HuntPack';
import useHuntAI from './useHuntAI';

/** Why planning a hunt with AI is not available here, or null when it is. */
export const useHuntPlanDisabledReason = (): string | null => {
  const { t_i18n } = useFormatter();
  const draftContext = useDraftContext();
  const { available, isEnterpriseEdition } = useHuntAI();
  if (draftContext) return t_i18n('Not available in a draft');
  if (!isEnterpriseEdition) return t_i18n('Planning with AI needs the Enterprise Edition');
  if (!available) return t_i18n('Planning with AI needs XTM One, not configured on this platform');
  return null;
};

/**
 * The quick starts of the first-use page, kept in the toolbar of the list of hunts once the platform holds hunts.
 * The XTM Hub link lives here: the toolbar of the list has no room for it next to the create button.
 */
const HuntQuickStartMenu = () => {
  const { t_i18n } = useFormatter();
  const planDisabledReason = useHuntPlanDisabledReason();
  const hubUrl = useHuntPackHubUrl();
  const [guided, setGuided] = useState<HuntGuidedKind | null>(null);
  const [planning, setPlanning] = useState(false);
  return (
    <>
      <Menu>
        <MenuTrigger asChild>
          <Button variant="secondary" data-testid="hunts-quick-start">{t_i18n('Quick start')}</Button>
        </MenuTrigger>
        <MenuContent align="end">
          <MenuItem startIcon={<PolicyOutlined fontSize="small" />} onSelect={() => setGuided('indicators')} data-testid="hunts-quick-start-indicators">
            {t_i18n('Hunt for indicators')}
          </MenuItem>
          <MenuItem startIcon={<RuleOutlined fontSize="small" />} onSelect={() => setGuided('sigma')} data-testid="hunts-quick-start-sigma">
            {t_i18n('Hunt with a Sigma rule')}
          </MenuItem>
          {planDisabledReason ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <span data-testid="hunts-quick-start-plan-disabled-reason">
                  <MenuItem startIcon={<AutoAwesomeOutlined fontSize="small" />} disabled aria-description={planDisabledReason} data-testid="hunts-quick-start-plan">
                    {t_i18n('Plan a hunt with AI')}
                  </MenuItem>
                </span>
              </TooltipTrigger>
              <TooltipContent>{planDisabledReason}</TooltipContent>
            </Tooltip>
          ) : (
            <MenuItem startIcon={<AutoAwesomeOutlined fontSize="small" />} onSelect={() => setPlanning(true)} data-testid="hunts-quick-start-plan">
              {t_i18n('Plan a hunt with AI')}
            </MenuItem>
          )}
          {hubUrl && (
            <MenuItem
              startIcon={<CloudDownloadOutlined fontSize="small" />}
              onSelect={() => window.open(hubUrl, '_blank', 'noopener,noreferrer')}
              data-testid="hunts-quick-start-hub"
            >
              {t_i18n('Import from XTM Hub')}
            </MenuItem>
          )}
        </MenuContent>
      </Menu>
      {guided && <HuntGuidedCreation kind={guided} open onClose={() => setGuided(null)} />}
      {planning && <HuntPlanDialog open onClose={() => setPlanning(false)} entityIds={[]} />}
    </>
  );
};

export default HuntQuickStartMenu;
