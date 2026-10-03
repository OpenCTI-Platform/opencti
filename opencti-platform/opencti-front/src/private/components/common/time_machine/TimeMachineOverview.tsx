import React, { ReactNode, Suspense } from 'react';
import { Alert, Box } from '@mui/material';
import { HistoryOutlined } from '@mui/icons-material';
import { IconButton, Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import { useTimeMachine } from './TimeMachineContext';
import TimeMachineSlider from './TimeMachineSlider';
import EntityAsOfView from './EntityAsOfView';
import SinceLastVisitChips from './SinceLastVisitChips';
import { presetRange } from './timeMachineUtils';

/**
 * Toggles the read-only "View as of" mode of the overview.
 */
export const TimeMachineAsOfButton = () => {
  const { t_i18n } = useFormatter();
  const { asOfDate, setAsOfDate } = useTimeMachine();
  const label = asOfDate ? t_i18n('Back to the current knowledge') : t_i18n('View as of');
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <IconButton
          priority="tertiary"
          aria-label={label}
          active={!!asOfDate}
          data-testid="time-machine-toggle"
          icon={<HistoryOutlined fontSize="small" />}
          onClick={() => setAsOfDate(asOfDate ? null : presetRange('30d').from)}
        />
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
};

interface TimeMachineOverviewProps {
  entityId: string;
  children: ReactNode;
}

/**
 * Overview of an entity with its time machine: what is new since the last visit of the user,
 * and the read-only view of the entity as it was at a past date.
 */
const TimeMachineOverview = ({ entityId, children }: TimeMachineOverviewProps) => {
  const { t_i18n, fldt } = useFormatter();
  const { asOfDate, setAsOfDate } = useTimeMachine();
  if (!asOfDate) {
    return (
      <>
        <SinceLastVisitChips entityId={entityId} />
        {children}
      </>
    );
  }
  return (
    <Box data-testid="time-machine-overview">
      <Alert
        severity="info"
        role="status"
        sx={{ marginBottom: 2, alignItems: 'center' }}
        action={(
          <Button variant="secondary" onClick={() => setAsOfDate(null)}>
            {t_i18n('Back to the current knowledge')}
          </Button>
        )}
      >
        {t_i18n('Read-only view of this entity as it was on')} {fldt(asOfDate)}
      </Alert>
      <Box sx={{ marginBottom: 3 }}>
        <Card title={t_i18n('Time machine')}>
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <TimeMachineSlider entityId={entityId} value={asOfDate} onChange={setAsOfDate} />
          </Suspense>
        </Card>
      </Box>
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <EntityAsOfView entityId={entityId} date={asOfDate} />
      </Suspense>
    </Box>
  );
};

export default TimeMachineOverview;
