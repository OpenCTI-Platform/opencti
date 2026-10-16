import React from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { Link } from 'react-router';
import { useTheme } from '@mui/styles';
import { CheckCircleOutlined, WarningAmberOutlined } from '@mui/icons-material';
import { Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import EEChip from '@components/common/entreprise_edition/EEChip';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import useGranted, { SETTINGS_SETPARAMETERS } from '../../../utils/hooks/useGranted';
import useHuntAI from './useHuntAI';
import { HUNT_DOCS } from './hunt-utils';
import { HuntsSetupChecklistQuery } from './__generated__/HuntsSetupChecklistQuery.graphql';

export const HUNT_CONNECTOR_CATALOG_PATH = '/dashboard/data/ingestion/catalog';
export const XTM_ONE_SETTINGS_PATH = '/dashboard/settings/experience';

const huntsSetupChecklistQuery = graphql`
  query HuntsSetupChecklistQuery {
    huntConnectors(onlyAlive: false) {
      id
      active
      supports_indicators
    }
  }
`;

export interface HuntsSetupState {
  connectorsCount: number;
  aliveCount: number;
  indicatorsCount: number;
  xtmOneConfigured: boolean;
  isEnterpriseEdition: boolean;
}

/** Whether every prerequisite of the hunting area is met: a live hunt connector, XTM One and the Enterprise Edition. */
export const isHuntsSetupComplete = (state: HuntsSetupState) => state.aliveCount > 0 && state.xtmOneConfigured && state.isEnterpriseEdition;

export const useHuntsSetupState = (): HuntsSetupState => {
  const { huntConnectors } = useLazyLoadQuery<HuntsSetupChecklistQuery>(huntsSetupChecklistQuery, {}, { fetchPolicy: 'store-and-network' });
  const { xtmOneConfigured, isEnterpriseEdition } = useHuntAI();
  const alive = huntConnectors.filter((connector) => connector.active);
  return {
    connectorsCount: huntConnectors.length,
    aliveCount: alive.length,
    indicatorsCount: alive.filter((connector) => connector.supports_indicators).length,
    xtmOneConfigured,
    isEnterpriseEdition,
  };
};

const Row = ({ met, children, action, testId }: { met: boolean; children: React.ReactNode; action?: React.ReactNode; testId: string }) => {
  const theme = useTheme<Theme>();
  return (
    <li style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }} data-testid={testId} data-status={met ? 'met' : 'unmet'}>
      {met
        ? <CheckCircleOutlined fontSize="small" style={{ color: theme.palette.success.main, flexShrink: 0 }} aria-hidden />
        : <WarningAmberOutlined fontSize="small" style={{ color: theme.palette.warn.main, flexShrink: 0 }} aria-hidden />}
      <Text variant="content-compact" style={{ flex: '1 1 0', minWidth: 0 }}>{children}</Text>
      {action}
    </li>
  );
};

/**
 * What the platform needs before hunts can run, with the live state of each prerequisite and its next action; shown on
 * the Hunts page until every prerequisite is met.
 */
const HuntsSetupChecklist = ({ state }: { state: HuntsSetupState }) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const canSetParameters = useGranted([SETTINGS_SETPARAMETERS]);
  let connectorsSentence: string;
  if (state.connectorsCount === 0) {
    connectorsSentence = t_i18n('Hunt connectors: none deployed. A hunt runs on your SIEM, EDR or data lake through a hunt connector.');
  } else if (state.aliveCount === 0) {
    connectorsSentence = t_i18n('Hunt connectors: {count} deployed, none answers. Check that they run.', { values: { count: n(state.connectorsCount) } });
  } else {
    connectorsSentence = t_i18n('Hunt connectors: {count} active', { values: { count: n(state.aliveCount) } });
  }
  return (
    <div data-testid="hunts-setup-checklist">
      <Text variant="content-compact-bold" as="h3" style={{ margin: `0 0 ${theme.spacing(1)} 0` }}>{t_i18n('Before your first hunt')}</Text>
      <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: theme.spacing(0.75) }}>
        <Row
          met={state.aliveCount > 0}
          testId="hunts-setup-connectors"
          action={state.aliveCount === 0 ? (
            <>
              <Button variant="secondary" size="small" component={Link} to={HUNT_CONNECTOR_CATALOG_PATH} data-testid="hunts-setup-deploy-connector">
                {t_i18n('Deploy a hunt connector')}
              </Button>
              <Button variant="secondary" size="small" href={HUNT_DOCS.connectors} target="_blank" rel="noopener noreferrer">{t_i18n('Required permissions')}</Button>
            </>
          ) : undefined}
        >
          {connectorsSentence}
        </Row>
        {state.aliveCount > 0 && (
          <Row met={state.indicatorsCount > 0} testId="hunts-setup-indicators">
            {state.indicatorsCount > 0
              ? t_i18n('{count, plural, one {Indicator lookups: # active hunt connector supports them} other {Indicator lookups: # active hunt connectors support them}}', { values: { count: state.indicatorsCount } })
              : t_i18n('Indicator lookups: no active hunt connector supports them, hunt with a Sigma rule or a native query instead')}
          </Row>
        )}
        <Row
          met={state.xtmOneConfigured}
          testId="hunts-setup-xtm-one"
          action={!state.xtmOneConfigured ? (
            canSetParameters
              ? <Button variant="tertiary" size="small" component={Link} to={XTM_ONE_SETTINGS_PATH}>{t_i18n('Open the settings')}</Button>
              : <Text variant="content-caption" style={{ color: theme.palette.text.secondary }}>{t_i18n('Ask your administrator')}</Text>
          ) : undefined}
        >
          {state.xtmOneConfigured
            ? t_i18n('XTM One: configured, hunts can be planned and triaged with AI')
            : t_i18n('XTM One: not configured, needed to plan a hunt with AI')}
        </Row>
        <Row met={state.isEnterpriseEdition} testId="hunts-setup-ee" action={!state.isEnterpriseEdition ? <EEChip /> : undefined}>
          {state.isEnterpriseEdition
            ? t_i18n('Enterprise Edition: scheduled and standing hunts and AI planning are available')
            : t_i18n('Enterprise Edition: needed for scheduled and standing hunts and AI planning; manual hunts work without it')}
        </Row>
      </ul>
    </div>
  );
};

export default HuntsSetupChecklist;
