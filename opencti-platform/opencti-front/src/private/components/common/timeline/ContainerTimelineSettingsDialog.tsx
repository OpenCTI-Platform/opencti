import React, { useEffect, useState } from 'react';
import {
  Checkbox,
  Dialog,
  DialogBody,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogTitle,
  Select,
  SelectContent,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { timelineSettingsUpdateMutation } from './ContainerTimelineMutations';
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

export interface TimelineSettingsValues {
  enabled_lanes: readonly string[];
  default_grouping: string;
  default_zoom_window: string;
  hidden_kinds: readonly string[];
}

interface ContainerTimelineSettingsDialogProps {
  containerId: string;
  open: boolean;
  settings: TimelineSettingsValues;
  onClose: () => void;
  onSaved: () => void;
}

const toggle = (values: readonly string[], value: string) => (values.includes(value) ? values.filter((v) => v !== value) : [...values, value]);

const ContainerTimelineSettingsDialog = ({ containerId, open, settings, onClose, onSaved }: ContainerTimelineSettingsDialogProps) => {
  const { t_i18n } = useFormatter();
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
      onCompleted: () => {
        setSaving(false);
        MESSAGING$.notifySuccess(t_i18n('The timeline settings have been saved'));
        onSaved();
        onClose();
      },
      onError: () => setSaving(false),
    });
  };

  return (
    <Dialog open={open} onOpenChange={(isOpen) => !isOpen && onClose()}>
      <DialogContent style={{ maxWidth: 720 }}>
        <DialogTitle>{t_i18n('Timeline settings')}</DialogTitle>
        <DialogDescription>{t_i18n('These settings apply to every user of this case timeline.')}</DialogDescription>
        <DialogBody>
          <div style={{ fontWeight: 600, marginBottom: 6 }}>{t_i18n('Enabled lanes')}</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6 }}>
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
          <div style={{ display: 'flex', gap: 16, marginTop: 20 }}>
            <div style={{ flex: 1 }}>
              <Select value={values.default_grouping} onValueChange={(value) => setValues({ ...values, default_grouping: value })}>
                <SelectLabel>{t_i18n('Default grouping')}</SelectLabel>
                <SelectTrigger aria-label={t_i18n('Default grouping')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {TIMELINE_GROUPINGS.map((grouping) => (
                    <SelectItem key={grouping} value={grouping}>{t_i18n(TIMELINE_GROUPING_LABELS[grouping])}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div style={{ flex: 1 }}>
              <Select value={values.default_zoom_window} onValueChange={(value) => setValues({ ...values, default_zoom_window: value })}>
                <SelectLabel>{t_i18n('Default zoom window')}</SelectLabel>
                <SelectTrigger aria-label={t_i18n('Default zoom window')}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {TIMELINE_ZOOM_WINDOWS.map((zoom) => (
                    <SelectItem key={zoom} value={zoom}>{t_i18n(TIMELINE_ZOOM_LABELS[zoom])}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div style={{ fontWeight: 600, margin: '20px 0 6px 0' }}>{t_i18n('Kinds hidden by default')}</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6, maxHeight: 260, overflowY: 'auto' }}>
            {TIMELINE_KINDS.map((kind) => (
              <Checkbox
                key={kind}
                label={t_i18n(TIMELINE_KIND_LABELS[kind])}
                checked={values.hidden_kinds.includes(kind)}
                onCheckedChange={() => setValues({ ...values, hidden_kinds: toggle(values.hidden_kinds, kind) })}
              />
            ))}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="secondary" onClick={onClose} disabled={saving}>{t_i18n('Cancel')}</Button>
          <Button onClick={save} disabled={saving || values.enabled_lanes.length === 0} data-testid="timeline-settings-save">{t_i18n('Save')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
};

export default ContainerTimelineSettingsDialog;
