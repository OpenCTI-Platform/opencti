import React, { useContext, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import { AutoAwesomeOutlined, MenuBookOutlined } from '@mui/icons-material';
import { Crosshairs } from 'mdi-material-ui';
import { Hero, HeroBody, HeroHeader, Text, Thumbnail, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { UserContext } from '../../../utils/hooks/useAuth';
import useDraftContext from '../../../utils/hooks/useDraftContext';
import { isNotEmptyField } from '../../../utils/utils';
import { HuntCreationDrawer, insertCreatedHunt } from './HuntCreation';
import HuntPlanDialog from './HuntPlanDialog';
import useHuntAI from './useHuntAI';
import { HuntsFirstUseQuery } from './__generated__/HuntsFirstUseQuery.graphql';
import { HuntsListQuery$variables } from './__generated__/HuntsListQuery.graphql';

export const HUNTS_DOCUMENTATION_URL = 'https://docs.opencti.io/latest/usage/hunts/';

const huntsFirstUseQuery = graphql`
  query HuntsFirstUseQuery {
    hunts(first: 1) {
      pageInfo {
        globalCount
      }
    }
  }
`;

interface HuntsFirstUseHeroProps {
  paginationOptions: HuntsListQuery$variables;
  onHuntCreated: () => void;
}

/** First use of the Hunts area: what a hunt does and the three ways to get the first one. */
export const HuntsFirstUseHero = ({ paginationOptions, onHuntCreated }: HuntsFirstUseHeroProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { settings, isXTMHubAccessible } = useContext(UserContext);
  const draftContext = useDraftContext();
  const { available: aiAvailable, isEnterpriseEdition } = useHuntAI();
  const [creating, setCreating] = useState(false);
  const [planning, setPlanning] = useState(false);
  const hubUrl = isXTMHubAccessible && isNotEmptyField(settings?.platform_xtmhub_url)
    ? `${settings?.platform_xtmhub_url}/redirect/opencti_hunt_packs?platform_id=${settings?.id}`
    : null;
  let planDisabledReason: string | null = null;
  if (draftContext) {
    planDisabledReason = t_i18n('Not available in a draft');
  } else if (!isEnterpriseEdition) {
    planDisabledReason = t_i18n('Enterprise Edition');
  } else if (!aiAvailable) {
    planDisabledReason = t_i18n('XTM One is not configured');
  }
  const planButton = (
    <Button
      variant="secondary"
      intent="ai"
      startIcon={<AutoAwesomeOutlined fontSize="small" />}
      disabled={planDisabledReason !== null}
      onClick={() => setPlanning(true)}
      data-testid="hunts-first-use-plan"
    >
      {t_i18n('Plan a hunt with AI')}
    </Button>
  );
  return (
    <Hero data-testid="hunts-first-use">
      <HeroHeader icon={<Thumbnail elevation={2}><Crosshairs fontSize="small" /></Thumbnail>}>
        <Text variant="title-sm" as="h2">{t_i18n('Hunt for threats in your environment')}</Text>
      </HeroHeader>
      <HeroBody>
        <Text variant="content-compact" style={{ display: 'block', maxWidth: 760 }}>
          {t_i18n('A hunt tests a hypothesis about a threat in your own telemetry: hunt connectors run its Sigma rule or native queries on your SIEM, EDR or data lake, and every run records what it found and its verdict.')}
        </Text>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: theme.spacing(1), marginTop: theme.spacing(2) }}>
          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <>
              <Button onClick={() => setCreating(true)} data-testid="hunts-first-use-create">{t_i18n('Create a hunt')}</Button>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: theme.spacing(0.5) }}>
                {planDisabledReason ? (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span tabIndex={0} aria-label={`${t_i18n('Plan a hunt with AI')}: ${planDisabledReason}`}>{planButton}</span>
                    </TooltipTrigger>
                    <TooltipContent>{planDisabledReason}</TooltipContent>
                  </Tooltip>
                ) : planButton}
                {!isEnterpriseEdition && <EEChip />}
              </span>
              {hubUrl && (
                <Button variant="secondary" href={hubUrl} target="_blank" rel="noopener noreferrer" data-testid="hunts-first-use-hub">
                  {t_i18n('Import from XTM Hub')}
                </Button>
              )}
            </>
          </Security>
          <Button
            variant="tertiary"
            startIcon={<MenuBookOutlined fontSize="small" />}
            href={HUNTS_DOCUMENTATION_URL}
            target="_blank"
            rel="noopener noreferrer"
            data-testid="hunts-first-use-docs"
          >
            {t_i18n('Read the documentation')}
          </Button>
        </div>
      </HeroBody>
      {creating && (
        <HuntCreationDrawer
          open
          onClose={() => setCreating(false)}
          initialValues={{}}
          updater={insertCreatedHunt(paginationOptions)}
          onCreated={onHuntCreated}
        />
      )}
      <HuntPlanDialog open={planning} onClose={() => setPlanning(false)} entityIds={[]} />
    </Hero>
  );
};

interface HuntsFirstUseProps {
  paginationOptions: HuntsListQuery$variables;
  children: React.ReactNode;
}

/** The Hunts list once the platform holds a hunt the user can see; the first-use hero before that. */
const HuntsFirstUse = ({ paginationOptions, children }: HuntsFirstUseProps) => {
  const [fetchKey, setFetchKey] = useState(0);
  const { hunts } = useLazyLoadQuery<HuntsFirstUseQuery>(huntsFirstUseQuery, {}, { fetchPolicy: 'store-and-network', fetchKey });
  if ((hunts?.pageInfo?.globalCount ?? 0) === 0) {
    return <HuntsFirstUseHero paginationOptions={paginationOptions} onHuntCreated={() => setFetchKey((key) => key + 1)} />;
  }
  return <>{children}</>;
};

export default HuntsFirstUse;
