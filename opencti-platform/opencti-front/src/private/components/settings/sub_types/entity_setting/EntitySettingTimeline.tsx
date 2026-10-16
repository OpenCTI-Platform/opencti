import React from 'react';
import { useFragment } from 'react-relay';
import { useTheme } from '@mui/material/styles';
import { Switch, Text } from '@filigran/design-system';
import Card from '@common/card/Card';
import { useFormatter } from '../../../../../components/i18n';
import useApiMutation from '../../../../../utils/hooks/useApiMutation';
import {
  resolveTimelineHeadlineDates,
  TIMELINE_ANCHOR_KEYS,
  TIMELINE_ANCHOR_LABELS,
  TIMELINE_DEFAULT_HEADLINE_DATES,
  timelineAnchorHelp,
  type TimelineAnchorKey,
  timelineContainerHasTasks,
} from '../../../common/timeline/timelineUtils';
import { useSubTypeOutletContext } from '../SubTypeOutletContext';
import { entitySettingsFragment } from './EntitySettingsFragment';
import { entitySettingPatch } from './EntitySettingSettings';
import type { EntitySettingsFragment_entitySetting$key } from './__generated__/EntitySettingsFragment_entitySetting.graphql';

interface EntitySettingTimelineDatesProps {
  entityType: string;
  headlineDates: readonly TimelineAnchorKey[];
  disabled?: boolean;
  onChange: (headlineDates: TimelineAnchorKey[]) => void;
}

/** One switch per headline date, in the order of the timelines; the last one shown cannot be switched off. */
export const EntitySettingTimelineDates = ({ entityType, headlineDates, disabled = false, onChange }: EntitySettingTimelineDatesProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const withTasks = timelineContainerHasTasks(entityType);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }} data-testid="entity-setting-timeline">
      <Text variant="content-base" as="p" style={{ margin: 0 }}>
        {t_i18n('The dates shown above the timelines of this type. They are marked on the lanes, offered as filters of the lists, and notified by the Timeline anchor changed trigger. At least one date stays shown.')}
      </Text>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: theme.spacing(2, 3) }}>
        {TIMELINE_ANCHOR_KEYS.map((key) => {
          const shown = headlineDates.includes(key);
          return (
            <div key={key} data-testid={`entity-setting-timeline-${key}`}>
              <Switch
                name={`timeline_headline_dates.${key}`}
                checked={shown}
                disabled={disabled || (shown && headlineDates.length === 1)}
                label={t_i18n(TIMELINE_ANCHOR_LABELS[key])}
                onCheckedChange={(checked: boolean) => onChange(TIMELINE_ANCHOR_KEYS.filter((anchor) => (anchor === key ? checked : headlineDates.includes(anchor))))}
              />
              <Text variant="content-caption" as="div" style={{ marginTop: theme.spacing(0.5), color: theme.palette.text.secondary }}>
                {t_i18n(timelineAnchorHelp(key, withTasks))}
              </Text>
              <Text variant="content-caption" as="div" style={{ color: theme.palette.text.secondary }}>
                {t_i18n(TIMELINE_DEFAULT_HEADLINE_DATES.includes(key) ? 'Shown by default' : 'Hidden by default')}
              </Text>
            </div>
          );
        })}
      </div>
    </div>
  );
};

/** Headline dates of the timelines of a type: shown above them, marked on their lanes, filters of the lists, notified. */
const EntitySettingTimeline = () => {
  const { t_i18n } = useFormatter();
  const { subType } = useSubTypeOutletContext();
  const entitySetting = useFragment<EntitySettingsFragment_entitySetting$key>(entitySettingsFragment, subType.settings);
  const [commit, patching] = useApiMutation(entitySettingPatch);
  return (
    <Card title={t_i18n('Headline dates')}>
      <EntitySettingTimelineDates
        entityType={entitySetting.target_type}
        headlineDates={resolveTimelineHeadlineDates(entitySetting.timeline_headline_dates)}
        disabled={patching}
        onChange={(next) => {
          if (next.length === 0) return;
          commit({ variables: { ids: [entitySetting.id], input: { key: 'timeline_headline_dates', value: next } } });
        }}
      />
    </Card>
  );
};

export default EntitySettingTimeline;
