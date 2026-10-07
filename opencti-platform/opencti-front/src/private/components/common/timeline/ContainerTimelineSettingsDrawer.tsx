import React, { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { useTheme } from '@mui/material/styles';
import { Checkbox, Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { notifyTimelineMutationErrors, timelineSettingsUpdateMutation } from './ContainerTimelineMutations';
import type {
  ContainerTimelineMutationsSettingsMutation,
  TimelineEventKind,
  TimelineGrouping as GqlTimelineGrouping,
  TimelineLane as GqlTimelineLane,
  TimelineZoomWindow as GqlTimelineZoomWindow,
} from './__generated__/ContainerTimelineMutationsSettingsMutation.graphql';
import {
  TIMELINE_GROUPING_LABELS,
  TIMELINE_GROUPINGS,
  TIMELINE_KIND_LABELS,
  TIMELINE_KINDS,
  TIMELINE_LANE_LABELS,
  TIMELINE_LANES,
  TIMELINE_ZOOM_LABELS,
  TIMELINE_ZOOM_WINDOWS,
} from './timelineUtils';
import useTimelineColors from './useTimelineColors';
import { TIMELINE_DOCUMENTATION_URL } from './ContainerTimelineStates';

export interface TimelineSettingsValues {
  enabled_lanes: readonly string[];
  default_grouping: string;
  default_zoom_window: string;
  hidden_kinds: readonly string[];
}

interface ContainerTimelineSettingsDrawerProps {
  containerId: string;
  open: boolean;
  settings: TimelineSettingsValues;
  onClose: () => void;
  onSaved: () => void;
}

const toggle = (values: readonly string[], value: string) => (values.includes(value) ? values.filter((v) => v !== value) : [...values, value]);

const SectionTitle = ({ children }: { children: React.ReactNode }) => {
  const colors = useTimelineColors();
  const theme = useTheme();
  return (
    <Text variant="content-compact-bold" as="div" style={{ color: colors.textSecondary, marginBottom: theme.spacing(0.75) }}>
      {children}
    </Text>
  );
};

/** Per-container timeline settings, shared by every user of the case timeline. */
const ContainerTimelineSettingsDrawer = ({ containerId, open, settings, onClose, onSaved }: ContainerTimelineSettingsDrawerProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const colors = useTimelineColors();
  const helpStyle = { color: colors.textSecondary, margin: theme.spacing(0.75, 0, 1) };
  const [values, setValues] = useState<TimelineSettingsValues>(settings);
  const [saving, setSaving] = useState(false);
  const [commit] = useApiMutation<ContainerTimelineMutationsSettingsMutation>(timelineSettingsUpdateMutation);

  useEffect(() => {
    if (open) setValues(settings);
  }, [open, settings]);

  const save = () => {
    setSaving(true);
    commit({
      variables: {
        containerId,
        input: {
          enabled_lanes: values.enabled_lanes as GqlTimelineLane[],
          default_grouping: values.default_grouping as GqlTimelineGrouping,
          default_zoom_window: values.default_zoom_window as GqlTimelineZoomWindow,
          hidden_kinds: values.hidden_kinds as TimelineEventKind[],
        },
      },
      onCompleted: (_, errors) => {
        setSaving(false);
        if (notifyTimelineMutationErrors(errors)) return;
        MESSAGING$.notifySuccess(t_i18n('The timeline settings have been saved'));
        onSaved();
        onClose();
      },
      onError: () => setSaving(false),
    });
  };

  return (
    <Drawer title={t_i18n('Timeline settings')} open={open} onClose={onClose}>
      <div data-testid="timeline-settings-drawer">
        <Text variant="content-base" as="div" style={{ marginBottom: theme.spacing(2.5) }}>{t_i18n('These settings apply to every user of this case timeline.')}</Text>
        <SectionTitle>{t_i18n('Enabled lanes')}</SectionTitle>
        <Text variant="content-caption" as="p" style={helpStyle}>{t_i18n('Lanes switched off are hidden for every reader of this case.')}</Text>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: theme.spacing(0.75) }}>
          {TIMELINE_LANES.map((lane) => (
            <Checkbox
              key={lane}
              label={t_i18n(TIMELINE_LANE_LABELS[lane])}
              checked={values.enabled_lanes.includes(lane)}
              // At least one lane stays enabled
              disabled={values.enabled_lanes.length === 1 && values.enabled_lanes.includes(lane)}
              onCheckedChange={() => setValues({ ...values, enabled_lanes: toggle(values.enabled_lanes, lane) })}
            />
          ))}
        </div>
        <div style={{ display: 'flex', gap: theme.spacing(2), marginTop: theme.spacing(2.5) }}>
          <div style={{ flex: 1 }}>
            <Select value={values.default_grouping} onValueChange={(value) => setValues({ ...values, default_grouping: value })}>
              <SelectLabel>{t_i18n('Default grouping')}</SelectLabel>
              <SelectTrigger aria-label={t_i18n('Default grouping')} aria-describedby="timeline-settings-grouping-help">
                <SelectValue />
              </SelectTrigger>
              <SelectContent aria-label={t_i18n('Default grouping')}>
                {TIMELINE_GROUPINGS.map((grouping) => (
                  <SelectItem key={grouping} value={grouping}>{t_i18n(TIMELINE_GROUPING_LABELS[grouping])}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Text id="timeline-settings-grouping-help" variant="content-caption" as="p" style={helpStyle}>
              {t_i18n('How events are grouped when the timeline opens, for every user of this case. Each reader can still change the grouping from the toolbar.')}
            </Text>
          </div>
          <div style={{ flex: 1 }}>
            <Select value={values.default_zoom_window} onValueChange={(value) => setValues({ ...values, default_zoom_window: value })}>
              <SelectLabel>{t_i18n('Default zoom window')}</SelectLabel>
              <SelectTrigger aria-label={t_i18n('Default zoom window')} aria-describedby="timeline-settings-zoom-help">
                <SelectValue />
              </SelectTrigger>
              <SelectContent aria-label={t_i18n('Default zoom window')}>
                {TIMELINE_ZOOM_WINDOWS.map((zoom) => (
                  <SelectItem key={zoom} value={zoom}>{t_i18n(TIMELINE_ZOOM_LABELS[zoom])}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Text id="timeline-settings-zoom-help" variant="content-caption" as="p" style={helpStyle}>
              {t_i18n('The period the lanes view shows when it opens, for every user of this case. Each reader can still choose another period, zoom or pan from the toolbar.')}
            </Text>
          </div>
        </div>
        <div style={{ marginTop: theme.spacing(2.5) }}>
          <SectionTitle>{t_i18n('Kinds hidden by default')}</SectionTitle>
          <Text variant="content-caption" as="p" style={helpStyle}>
            {t_i18n('Hidden kinds are left out of the default view of every reader; choosing them in the kinds filter shows them again.')}
          </Text>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: theme.spacing(0.75) }}>
          {TIMELINE_KINDS.map((kind) => (
            <Checkbox
              key={kind}
              label={t_i18n(TIMELINE_KIND_LABELS[kind])}
              checked={values.hidden_kinds.includes(kind)}
              // At least one kind stays visible
              disabled={!values.hidden_kinds.includes(kind) && TIMELINE_KINDS.every((other) => other === kind || values.hidden_kinds.includes(other))}
              onCheckedChange={() => setValues({ ...values, hidden_kinds: toggle(values.hidden_kinds, kind) })}
            />
          ))}
        </div>
        <Text variant="content-caption" as="div" style={{ marginTop: theme.spacing(2) }}>
          <Link to={`${TIMELINE_DOCUMENTATION_URL}#timeline-settings`} target="_blank" rel="noopener noreferrer" data-testid="timeline-settings-learn-more">
            {t_i18n('Learn more')}
          </Link>
        </Text>
        <FormButtonContainer>
          <Button variant="secondary" onClick={onClose} disabled={saving}>{t_i18n('Cancel')}</Button>
          <Button onClick={save} disabled={saving || values.enabled_lanes.length === 0} data-testid="timeline-settings-save">{t_i18n('Save')}</Button>
        </FormButtonContainer>
      </div>
    </Drawer>
  );
};

export default ContainerTimelineSettingsDrawer;
