import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router';
import Grid from '@mui/material/Grid';
import { useTheme } from '@mui/styles';
import { Chip, Text } from '@filigran/design-system';
import Card from '../../../components/common/card/Card';
import Label from '../../../components/common/label/Label';
import ExpandableMarkdown from '../../../components/ExpandableMarkdown';
import FieldOrEmpty from '../../../components/FieldOrEmpty';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import { resolveLink } from '../../../utils/Entity';
import { HuntRunStatusChip, HuntSourceKindChip, HuntStatusChip } from './HuntChips';
import { useHuntScheduleText } from './HuntSchedulePreview';
import { huntExtractsObservables, huntLastRunHits, huntRunsRecur, huntTypeLabel, parseHuntScopePlatformIds } from './hunt-utils';
import { useHuntDefaultObservableTypeNames } from './HuntRunProducesSection';
import useHuntConfiguration from './useHuntConfiguration';
import { HuntDetails_hunt$key } from './__generated__/HuntDetails_hunt.graphql';

const huntDetailsFragment = graphql`
  fragment HuntDetails_hunt on Hunt {
    id
    description
    hypothesis
    hunt_type
    hunt_status
    hunt_source_kind
    hunt_scope
    scopePlatforms {
      id
      name
      entity_type
    }
    hunt_schedule
    hunt_pir_activation
    hunt_pir_armed
    hunt_pir_armed_at
    time_window_hours
    escalation_threshold
    hunt_max_results
    expected_observables
    benign_patterns
    last_run_at
    last_run_status
    last_hits_count
    last_new_hits_count
    knownHits {
      distinct_count
      first_new_at
      last_new_at
    }
    next_run_at
    huntTargets {
      id
      entity_type
      representative {
        main
      }
    }
    huntTechniques {
      id
      entity_type
      name
      x_mitre_id
    }
    huntSources {
      id
      entity_type
      representative {
        main
      }
    }
  }
`;

interface EntityLinkItem {
  id: string;
  entity_type: string;
  label: string;
}

const EntityChips = ({ items, testId }: { items: EntityLinkItem[]; testId: string }) => {
  const theme = useTheme<Theme>();
  return (
    <FieldOrEmpty source={items}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: theme.spacing(0.5) }} data-testid={testId}>
        {items.map((item) => (
          <Link key={item.id} to={`${resolveLink(item.entity_type)}/${item.id}`}>
            <Chip label={item.label} />
          </Link>
        ))}
      </div>
    </FieldOrEmpty>
  );
};

interface HuntDetailsProps {
  data: HuntDetails_hunt$key;
}

const HuntDetails = ({ data }: HuntDetailsProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, fldt, n } = useFormatter();
  const scheduleText = useHuntScheduleText();
  const defaultTypes = useHuntDefaultObservableTypeNames();
  const { scheduleLookbackMinutes } = useHuntConfiguration();
  const hunt = useFragment(huntDetailsFragment, data);
  const advancedScope = hunt.hunt_scope && parseHuntScopePlatformIds(hunt.hunt_scope) === null;
  const scopeItems = (hunt.scopePlatforms ?? []).map((platform) => ({ id: platform.id, entity_type: platform.entity_type, label: platform.name }));
  const targets = (hunt.huntTargets ?? []).map((target) => ({ id: target.id, entity_type: target.entity_type, label: target.representative.main }));
  const techniques = (hunt.huntTechniques ?? []).map((technique) => ({
    id: technique.id,
    entity_type: technique.entity_type,
    label: technique.x_mitre_id ? `[${technique.x_mitre_id}] ${technique.name}` : technique.name,
  }));
  const sources = (hunt.huntSources ?? []).map((source) => ({ id: source.id, entity_type: source.entity_type, label: source.representative.main }));
  const textList = (values: ReadonlyArray<string> | null | undefined) => (
    <FieldOrEmpty source={values}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: theme.spacing(0.5) }}>
        {(values ?? []).map((value) => <Chip key={value} label={value} />)}
      </div>
    </FieldOrEmpty>
  );
  let pirState: string;
  if (!hunt.hunt_pir_activation) {
    pirState = t_i18n('Disabled');
  } else if (hunt.hunt_pir_armed) {
    pirState = t_i18n('Armed by a PIR since {date}', { values: { date: fldt(hunt.hunt_pir_armed_at) } });
  } else {
    pirState = t_i18n('Waiting for a PIR to flag one of its targets');
  }

  return (
    <div style={{ height: '100%' }} data-testid="hunt-details">
      <Card title={t_i18n('Details')}>
        <Grid container spacing={2}>
          <Grid item xs={12}>
            <Label>{t_i18n('Hypothesis')}</Label>
            <ExpandableMarkdown source={hunt.hypothesis} limit={400} />
          </Grid>
          <Grid item xs={12}>
            <Label>{t_i18n('Description')}</Label>
            <ExpandableMarkdown source={hunt.description} limit={400} />
          </Grid>
          <Grid item xs={6}>
            <Label>{t_i18n('Status')}</Label>
            <HuntStatusChip value={hunt.hunt_status} />
            <Label sx={{ marginTop: 2 }}>{t_i18n('Hunt type')}</Label>
            <Text variant="content-compact">{t_i18n(huntTypeLabel(hunt.hunt_type))}</Text>
            <Label sx={{ marginTop: 2 }}>{t_i18n('Origin')}</Label>
            <HuntSourceKindChip value={hunt.hunt_source_kind} />
            <Label sx={{ marginTop: 2 }}>{t_i18n('Schedule')}</Label>
            <Text variant="content-compact">{scheduleText(hunt.hunt_schedule)}</Text>
            <Label sx={{ marginTop: 2 }}>{t_i18n('Activation by PIR')}</Label>
            <Text variant="content-compact" data-testid="hunt-pir-state">{pirState}</Text>
          </Grid>
          <Grid item xs={6}>
            <Label>{t_i18n('Last run')}</Label>
            {hunt.last_run_at ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1), flexWrap: 'wrap' }}>
                <Text variant="content-compact">{fldt(hunt.last_run_at)}</Text>
                {hunt.last_run_status && <HuntRunStatusChip value={hunt.last_run_status} />}
                <Text variant="content-compact" data-testid="hunt-last-run-hits">{huntLastRunHits(hunt, t_i18n, n)}</Text>
              </div>
            ) : <Text variant="content-compact">-</Text>}
            <Label sx={{ marginTop: 2 }}>{t_i18n('Known hits')}</Label>
            <div data-testid="hunt-known-hits">
              <Text variant="content-compact">
                {t_i18n('{count, plural, =0 {No hit known yet} one {# distinct hit} other {# distinct hits}}', { values: { count: hunt.knownHits.distinct_count } })}
              </Text>
              {hunt.knownHits.first_new_at && hunt.knownHits.last_new_at && (
                <>
                  <Text variant="content-caption" style={{ display: 'block' }} data-testid="hunt-known-hits-first">
                    {t_i18n('First found {date}', { values: { date: fldt(hunt.knownHits.first_new_at) } })}
                  </Text>
                  <Text variant="content-caption" style={{ display: 'block' }} data-testid="hunt-known-hits-last">
                    {t_i18n('Last new hit {date}', { values: { date: fldt(hunt.knownHits.last_new_at) } })}
                  </Text>
                </>
              )}
            </div>
            <Label sx={{ marginTop: 2 }}>{t_i18n('Next run')}</Label>
            <Text variant="content-compact">{hunt.next_run_at ? fldt(hunt.next_run_at) : '-'}</Text>
            <Label sx={{ marginTop: 2 }}>{t_i18n('Time window')}</Label>
            <Text variant="content-compact">{t_i18n('{count} hours', { values: { count: hunt.time_window_hours } })}</Text>
            {huntRunsRecur(hunt) && (
              <Text variant="content-caption" style={{ display: 'block' }} data-testid="hunt-window-sentence">
                {t_i18n('Recurring runs: since the previous run, {minutes}-minute overlap', { values: { minutes: n(scheduleLookbackMinutes) } })}
              </Text>
            )}
            <Label sx={{ marginTop: 2 }}>{t_i18n('Escalation threshold')}</Label>
            <Text variant="content-compact">{t_i18n('{count, plural, =0 {No hit} one {# hit} other {# hits}}', { values: { count: hunt.escalation_threshold } })}</Text>
            <Label sx={{ marginTop: 2 }}>{t_i18n('Maximum results per run')}</Label>
            <Text variant="content-compact">{hunt.hunt_max_results ? n(hunt.hunt_max_results) : t_i18n('Platform default')}</Text>
          </Grid>
          <Grid item xs={12}>
            <Label>{t_i18n('Scope')}</Label>
            {advancedScope && <Text variant="content-compact">{t_i18n('Advanced scope filters')}</Text>}
            {!advancedScope && scopeItems.length === 0 && <Text variant="content-compact">{t_i18n('Every hunt-capable security platform')}</Text>}
            {!advancedScope && scopeItems.length > 0 && <EntityChips items={scopeItems} testId="hunt-scope-platforms" />}
          </Grid>
          <Grid item xs={4}>
            <Label>{t_i18n('Targets')}</Label>
            <EntityChips items={targets} testId="hunt-targets" />
          </Grid>
          <Grid item xs={4}>
            <Label>{t_i18n('Techniques')}</Label>
            <EntityChips items={techniques} testId="hunt-techniques" />
          </Grid>
          <Grid item xs={4}>
            <Label>{t_i18n('Sources')}</Label>
            <EntityChips items={sources} testId="hunt-sources" />
          </Grid>
          {huntExtractsObservables(hunt.hunt_type) && (
            <Grid item xs={6}>
              <Label>{t_i18n('Observables to extract from hits')}</Label>
              {(hunt.expected_observables ?? []).length > 0 ? textList((hunt.expected_observables ?? []).map((type) => t_i18n(`entity_${type}`))) : (
                <Text variant="content-compact" data-testid="hunt-default-observables">
                  {defaultTypes ? t_i18n('Default types: {types}', { values: { types: defaultTypes } }) : t_i18n('Platform default')}
                </Text>
              )}
            </Grid>
          )}
          <Grid item xs={6}>
            <Label>{t_i18n('Benign patterns')}</Label>
            {textList(hunt.benign_patterns)}
          </Grid>
        </Grid>
      </Card>
    </div>
  );
};

export default HuntDetails;
