import React, { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { useTheme } from '@mui/material/styles';
import { Checkbox, Chip, Text } from '@filigran/design-system';
import Button from '@common/button/Button';
import Drawer from '@components/common/drawer/Drawer';
import { useFormatter } from '../../../../components/i18n';
import FormButtonContainer from '../../../../components/common/form/FormButtonContainer';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useGranted, { SETTINGS_SETCUSTOMIZATION } from '../../../../utils/hooks/useGranted';
import { notifyTimelineMutationErrors, timelineSettingsUpdateMutation } from './ContainerTimelineMutations';
import type {
  ContainerTimelineMutationsSettingsMutation,
  TimelineEventKind,
  TimelineLane as GqlTimelineLane,
} from './__generated__/ContainerTimelineMutationsSettingsMutation.graphql';
import { TIMELINE_ANCHOR_LABELS, TIMELINE_KIND_LABELS, TIMELINE_KINDS, TIMELINE_LANE_LABELS, TIMELINE_LANES, type TimelineAnchorKey } from './timelineUtils';
import useTimelineColors from './useTimelineColors';
import { TIMELINE_DOCUMENTATION_URL } from './ContainerTimelineStates';

export interface TimelineSettingsValues {
  enabled_lanes: readonly string[];
  hidden_kinds: readonly string[];
}

interface ContainerTimelineSettingsDrawerProps {
  containerId: string;
  entityType: string;
  // Headline dates of the type, set in Settings > Customization
  headlineDates: readonly TimelineAnchorKey[];
  // Events of the rules reading a module not installed, with the name of that module
  inactiveKinds?: Readonly<Record<string, string>>;
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
const ContainerTimelineSettingsDrawer = ({
  containerId,
  entityType,
  headlineDates,
  inactiveKinds = {},
  open,
  settings,
  onClose,
  onSaved,
}: ContainerTimelineSettingsDrawerProps) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();
  const colors = useTimelineColors();
  const canCustomize = useGranted([SETTINGS_SETCUSTOMIZATION]);
  const helpStyle = { color: colors.textSecondary, margin: theme.spacing(0.75, 0, 1) };
  const [values, setValues] = useState<TimelineSettingsValues>(settings);
  const activeKinds = TIMELINE_KINDS.filter((kind) => !inactiveKinds[kind]);
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
        <Text variant="content-base" as="div" style={{ marginBottom: theme.spacing(2.5) }}>
          {t_i18n('These settings apply to every user of this case timeline. The zoom, the grouping and the view are kept for each reader, in their browser.')}
        </Text>
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
        <div style={{ marginTop: theme.spacing(2.5) }} data-testid="timeline-settings-headline-dates">
          <SectionTitle>{t_i18n('Headline dates')}</SectionTitle>
          <Text variant="content-caption" as="p" style={helpStyle}>
            {t_i18n('The same for every timeline of this type: they are chosen in the customization of the type.')}
          </Text>
          <div role="list" aria-label={t_i18n('Headline dates')} style={{ display: 'flex', flexWrap: 'wrap', gap: theme.spacing(0.75) }}>
            {headlineDates.map((key) => (
              <span role="listitem" key={key}><Chip label={t_i18n(TIMELINE_ANCHOR_LABELS[key])} size="sm" /></span>
            ))}
          </div>
          {canCustomize && (
            <Text variant="content-caption" as="div" style={{ marginTop: theme.spacing(1) }}>
              <Link to={`/dashboard/settings/customization/entity_types/${entityType}/timeline`} data-testid="timeline-settings-headline-dates-link">
                {t_i18n('Change the headline dates of this type')}
              </Link>
            </Text>
          )}
        </div>
        <div style={{ marginTop: theme.spacing(2.5) }}>
          <SectionTitle>{t_i18n('Events hidden by default')}</SectionTitle>
          <Text variant="content-caption" as="p" style={helpStyle}>
            {t_i18n('Hidden events are left out of the default view of every reader; choosing them in the events filter shows them again.')}
          </Text>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: theme.spacing(0.75) }}>
          {TIMELINE_KINDS.map((kind) => (
            <Checkbox
              key={kind}
              label={t_i18n(TIMELINE_KIND_LABELS[kind])}
              // No event of this type exists until the module that produces it is installed
              description={inactiveKinds[kind]
                ? t_i18n('Activates when the {module} module is installed', { values: { module: t_i18n(inactiveKinds[kind]) } })
                : undefined}
              checked={values.hidden_kinds.includes(kind)}
              // At least one event that can exist stays visible
              disabled={!!inactiveKinds[kind] || (!values.hidden_kinds.includes(kind) && activeKinds.every((other) => other === kind || values.hidden_kinds.includes(other)))}
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
