import React from 'react';
import { Field, useFormikContext } from 'formik';
import { useTheme } from '@mui/styles';
import { Text } from '@filigran/design-system';
import SelectFieldFds, { SelectItem } from '../../../components/fields/SelectFieldFds';
import TextField from '../../../components/TextField';
import { useFormatter } from '../../../components/i18n';
import type { Theme } from '../../../components/Theme';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import HuntSchedulePreview from './HuntSchedulePreview';
import type { HuntScheduleMode } from './hunt-schedule-utils';
import { HUNT_DOCS, buildHuntSchedule } from './hunt-utils';
import { HuntHelp } from './HuntLearnMore';
import HuntEELabel from './HuntEELabel';
import useHuntConfiguration from './useHuntConfiguration';

interface HuntScheduleFieldProps {
  modeName?: string;
  cronName?: string;
  disabled?: boolean;
}

interface ScheduleValues {
  [key: string]: unknown;
}

/**
 * Manual hunts run when started (Community Edition). Cron and standing hunts run autonomously
 * and require the Enterprise Edition; the options stay visible, disabled, with the EE marker.
 */
const HuntScheduleField = ({ modeName = 'schedule_mode', cronName = 'schedule_cron', disabled = false }: HuntScheduleFieldProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n, n } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { scheduleLookbackMinutes } = useHuntConfiguration();
  const { values } = useFormikContext<ScheduleValues>();
  const mode = (values[modeName] ?? 'manual') as HuntScheduleMode;
  const cron = String(values[cronName] ?? '');
  const schedule = buildHuntSchedule(mode, cron);

  return (
    <div data-testid="hunt-schedule-field">
      <Field
        component={SelectFieldFds}
        name={modeName}
        label={<HuntEELabel label={t_i18n('Schedule')} feature={t_i18n('Autonomous hunts')} />}
        disabled={disabled}
        fullWidth
        helpertext={<HuntHelp text={t_i18n('Manual: it runs when you click Run now. Scheduled: on a cron expression. Standing: when new knowledge matches its trigger filters.')} href={HUNT_DOCS.schedules} />}
      >
        <SelectItem value="manual">{t_i18n('Manual')}</SelectItem>
        <SelectItem value="cron" disabled={!isEnterpriseEdition}>{t_i18n('Scheduled (cron)')}</SelectItem>
        <SelectItem value="standing" disabled={!isEnterpriseEdition}>{t_i18n('Standing')}</SelectItem>
      </Field>
      {mode === 'cron' && (
        <div style={{ marginTop: theme.spacing(2) }}>
          <Field
            component={TextField}
            variant="outlined"
            name={cronName}
            label={t_i18n('Cron expression (UTC)')}
            placeholder="*/30 * * * *"
            required
            disabled={disabled}
            fullWidth
            helperText={<HuntHelp text={t_i18n('minute hour day-of-month month day-of-week, or @hourly, @daily, @weekly, @monthly')} href={HUNT_DOCS.schedules} />}
          />
        </div>
      )}
      {/* The helper line already says what a manual hunt does */}
      {mode !== 'manual' && <HuntSchedulePreview schedule={schedule} />}
      {mode !== 'manual' && (
        <Text variant="content-caption" style={{ display: 'block', marginTop: theme.spacing(0.5), color: theme.palette.text.secondary }} data-testid="hunt-schedule-window">
          <HuntHelp
            text={t_i18n('Each run searches since the previous one, with a {minutes}-minute overlap', { values: { minutes: n(scheduleLookbackMinutes) } })}
            href={HUNT_DOCS.hitCounting}
          />
        </Text>
      )}
    </div>
  );
};

export default HuntScheduleField;
