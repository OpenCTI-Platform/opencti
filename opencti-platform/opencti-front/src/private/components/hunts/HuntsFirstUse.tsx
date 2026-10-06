import React, { Suspense, useContext, useState } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import { AutoAwesomeOutlined, MenuBookOutlined, PolicyOutlined, RuleOutlined } from '@mui/icons-material';
import { Crosshairs } from 'mdi-material-ui';
import { Hero, HeroBody, HeroHeader, Text, Thumbnail } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '../../../components/common/card/Card';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import Security from '../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../utils/hooks/useGranted';
import { UserContext } from '../../../utils/hooks/useAuth';
import { isNotEmptyField } from '../../../utils/utils';
import { HuntCreationDrawer, insertCreatedHunt } from './HuntCreation';
import HuntGuidedCreation, { type HuntGuidedKind } from './HuntGuidedCreation';
import HuntPlanDialog from './HuntPlanDialog';
import { HuntPackImportButton } from './HuntPack';
import HuntsSetupChecklist, { isHuntsSetupComplete, useHuntsSetupState } from './HuntsSetupChecklist';
import { useHuntPlanDisabledReason } from './HuntQuickStartMenu';
import { HUNT_DOCS } from './hunt-utils';
import { HuntsFirstUseQuery } from './__generated__/HuntsFirstUseQuery.graphql';
import { HuntsListQuery$variables } from './__generated__/HuntsListQuery.graphql';

export const HUNTS_DOCUMENTATION_URL = HUNT_DOCS.hunts;

const huntsFirstUseQuery = graphql`
  query HuntsFirstUseQuery {
    hunts(first: 1) {
      pageInfo {
        globalCount
      }
    }
  }
`;

interface StartingPointProps {
  icon: React.ReactNode;
  title: string;
  description: string;
  testId: string;
  children: React.ReactNode;
}

const StartingPoint = ({ icon, title, description, testId, children }: StartingPointProps) => {
  const theme = useTheme<Theme>();
  return (
    <div style={{ flex: '1 1 260px', minWidth: 260 }} data-testid={testId}>
      <Card>
        <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1), height: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
            {icon}
            <Text variant="title-sm" as="h3" style={{ margin: 0 }}>{title}</Text>
          </div>
          <Text variant="content-compact" style={{ color: theme.palette.text.secondary, flex: 1 }}>{description}</Text>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: theme.spacing(1), alignItems: 'center' }}>{children}</div>
        </div>
      </Card>
    </div>
  );
};

interface HuntsFirstUseHeroProps {
  paginationOptions: HuntsListQuery$variables;
  onHuntCreated: () => void;
}

/** First use of the Hunts area: what a hunt does, what the platform needs, and three ways to start, each two minutes. */
export const HuntsFirstUseHero = ({ paginationOptions, onHuntCreated }: HuntsFirstUseHeroProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const { settings, isXTMHubAccessible } = useContext(UserContext);
  const planDisabledReason = useHuntPlanDisabledReason();
  const setupState = useHuntsSetupState();
  const indicatorsUnsupported = setupState.aliveCount > 0 && setupState.indicatorsCount === 0;
  const [creating, setCreating] = useState(false);
  const [planning, setPlanning] = useState(false);
  const [guided, setGuided] = useState<HuntGuidedKind | null>(null);
  const hubUrl = isXTMHubAccessible && isNotEmptyField(settings?.platform_xtmhub_url)
    ? `${settings?.platform_xtmhub_url}/redirect/opencti_hunt_packs?platform_id=${settings?.id}`
    : null;
  return (
    <div data-testid="hunts-first-use" style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
      <Hero>
        <HeroHeader icon={<Thumbnail elevation={2}><Crosshairs fontSize="small" /></Thumbnail>}>
          <Text variant="title-sm" as="h2">{t_i18n('Hunt for threats in your environment')}</Text>
        </HeroHeader>
        <HeroBody>
          <Text variant="content-compact" style={{ display: 'block', maxWidth: 760 }}>
            {t_i18n('A hunt looks for a threat in your own telemetry: hunt connectors search your SIEM, EDR or data lake for its indicators or run its detection rule, and every run records what it found and its verdict.')}
          </Text>
          <div style={{ marginTop: theme.spacing(2) }}>
            <HuntsSetupChecklist state={setupState} />
          </div>
        </HeroBody>
      </Hero>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: theme.spacing(2) }} data-testid="hunts-first-use-starting-points">
          <StartingPoint
            icon={<PolicyOutlined fontSize="small" aria-hidden />}
            title={t_i18n('Hunt for indicators')}
            description={t_i18n('Look for IP addresses, domains, URLs or file hashes in your telemetry: paste them, pick indicators, or take those of a report or a threat. No query language.')}
            testId="hunts-first-use-indicators"
          >
            <Button
              variant={indicatorsUnsupported ? 'secondary' : 'primary'}
              onClick={() => setGuided('indicators')}
              aria-describedby={indicatorsUnsupported ? 'hunts-first-use-indicators-reason' : undefined}
              data-testid="hunts-first-use-indicators-start"
            >
              {t_i18n('Hunt for indicators')}
            </Button>
            {indicatorsUnsupported && (
              <Text
                id="hunts-first-use-indicators-reason"
                variant="content-caption"
                style={{ display: 'block', width: '100%', color: theme.palette.warn.main }}
                data-testid="hunts-first-use-indicators-reason"
              >
                {t_i18n('No active hunt connector looks up indicators yet: the hunt would be saved as a draft')}
              </Text>
            )}
          </StartingPoint>
          <StartingPoint
            icon={<RuleOutlined fontSize="small" aria-hidden />}
            title={t_i18n('Hunt with a detection rule (Sigma)')}
            description={t_i18n('Paste a Sigma rule: the hunt connector translates it for your SIEM or EDR and runs it on the period you choose.')}
            testId="hunts-first-use-sigma"
          >
            <Button variant="primary" onClick={() => setGuided('sigma')} data-testid="hunts-first-use-sigma-start">{t_i18n('Hunt with a Sigma rule')}</Button>
          </StartingPoint>
          <StartingPoint
            icon={<AutoAwesomeOutlined fontSize="small" aria-hidden />}
            title={t_i18n('Plan a hunt with AI or import a hunt pack')}
            description={t_i18n('Let the AI planner write the hypothesis and the rule from a threat or a report, or import hunts shared as a hunt pack.')}
            testId="hunts-first-use-ai"
          >
            <Button
              variant="secondary"
              intent="ai"
              startIcon={<AutoAwesomeOutlined fontSize="small" />}
              disabled={planDisabledReason !== null}
              onClick={() => setPlanning(true)}
              aria-describedby={planDisabledReason ? 'hunts-first-use-plan-reason' : undefined}
              data-testid="hunts-first-use-plan"
            >
              {t_i18n('Plan a hunt with AI')}
            </Button>
            <HuntPackImportButton paginationOptions={paginationOptions} />
            {hubUrl && (
              <Button variant="tertiary" href={hubUrl} target="_blank" rel="noopener noreferrer" data-testid="hunts-first-use-hub">
                {t_i18n('Browse XTM Hub')}
              </Button>
            )}
            {planDisabledReason && (
              <Text id="hunts-first-use-plan-reason" variant="content-caption" style={{ display: 'block', width: '100%', color: theme.palette.text.secondary }} data-testid="hunts-first-use-plan-reason">
                {planDisabledReason}
              </Text>
            )}
          </StartingPoint>
        </div>
      </Security>
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: theme.spacing(1) }}>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <Button variant="tertiary" onClick={() => setCreating(true)} data-testid="hunts-first-use-create">{t_i18n('Create a hunt with every option')}</Button>
        </Security>
        <Button
          variant="tertiary"
          startIcon={<MenuBookOutlined fontSize="small" />}
          href={HUNT_DOCS.firstHunt}
          target="_blank"
          rel="noopener noreferrer"
          data-testid="hunts-first-use-docs"
        >
          {t_i18n('Your first hunt, step by step')}
        </Button>
      </div>
      {creating && (
        <HuntCreationDrawer
          open
          onClose={() => setCreating(false)}
          initialValues={{}}
          updater={insertCreatedHunt(paginationOptions)}
          onCreated={onHuntCreated}
        />
      )}
      {guided && <HuntGuidedCreation kind={guided} open onClose={() => setGuided(null)} />}
      <HuntPlanDialog open={planning} onClose={() => setPlanning(false)} entityIds={[]} />
    </div>
  );
};

/** Above the list of hunts: the setup checklist, until every prerequisite is met. */
const HuntsSetupBanner = () => {
  const theme = useTheme<Theme>();
  const setupState = useHuntsSetupState();
  if (isHuntsSetupComplete(setupState)) {
    return null;
  }
  return (
    <div style={{ marginBottom: theme.spacing(2) }} data-testid="hunts-setup-banner">
      <Card>
        <HuntsSetupChecklist state={setupState} />
      </Card>
    </div>
  );
};

interface HuntsFirstUseProps {
  paginationOptions: HuntsListQuery$variables;
  children: React.ReactNode;
}

/** The Hunts list once the platform holds a hunt the user can see; the first-use page before that. */
const HuntsFirstUse = ({ paginationOptions, children }: HuntsFirstUseProps) => {
  const [fetchKey, setFetchKey] = useState(0);
  const { hunts } = useLazyLoadQuery<HuntsFirstUseQuery>(huntsFirstUseQuery, {}, { fetchPolicy: 'store-and-network', fetchKey });
  if ((hunts?.pageInfo?.globalCount ?? 0) === 0) {
    return <HuntsFirstUseHero paginationOptions={paginationOptions} onHuntCreated={() => setFetchKey((key) => key + 1)} />;
  }
  return (
    <>
      <Suspense fallback={null}>
        <HuntsSetupBanner />
      </Suspense>
      {children}
    </>
  );
};

export default HuntsFirstUse;
