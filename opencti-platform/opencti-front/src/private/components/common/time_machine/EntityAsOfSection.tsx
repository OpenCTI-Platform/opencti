import React, { Suspense, useCallback, useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { Alert, Box } from '@mui/material';
import Button from '@common/button/Button';
import Card from '@common/card/Card';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import TimeMachineSlider from './TimeMachineSlider';
import EntityAsOfView from './EntityAsOfView';
import { AS_OF_SEARCH_PARAM, isValidDate, presetRange } from './timeMachineUtils';

/**
 * Date of the as-of view, kept in the URL so the view can be shared and survives a reload.
 * Without a date in the URL, the view opens 30 days back and writes that date in the URL.
 */
const useAsOfDate = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const rawDate = searchParams.get(AS_OF_SEARCH_PARAM);
  const defaultDate = useMemo(() => presetRange('30d').from, []);
  const hasDate = isValidDate(rawDate);
  const asOfDate = hasDate ? rawDate : defaultDate;
  const setAsOfDate = useCallback((date: string) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.set(AS_OF_SEARCH_PARAM, date);
      return next;
    }, { replace: true });
  }, [setSearchParams]);
  useEffect(() => {
    if (!hasDate) setAsOfDate(defaultDate);
  }, [hasDate, defaultDate, setAsOfDate]);
  return { asOfDate, setAsOfDate };
};

interface EntityAsOfSectionProps {
  entityId: string;
  basePath: string;
}

/**
 * "View as of" section of the Changes tab: the read-only view of the entity as it was at a past date,
 * with the time slider to move along its history.
 */
const EntityAsOfSection = ({ entityId, basePath }: EntityAsOfSectionProps) => {
  const { t_i18n, fldt } = useFormatter();
  const navigate = useNavigate();
  const { asOfDate, setAsOfDate } = useAsOfDate();
  return (
    <Box data-testid="time-machine-as-of">
      <Alert
        severity="info"
        role="status"
        sx={{ marginBottom: 2, alignItems: 'center' }}
        action={(
          <Button variant="secondary" onClick={() => navigate(`${basePath}/overview`)}>
            {t_i18n('Back to the current knowledge')}
          </Button>
        )}
      >
        {t_i18n('Read-only view of this entity as it was on {date}', { values: { date: fldt(asOfDate) } })}
      </Alert>
      <Box sx={{ marginBottom: 3 }}>
        <Card title={t_i18n('Time machine')}>
          <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <TimeMachineSlider entityId={entityId} value={asOfDate} onChange={setAsOfDate} />
          </Suspense>
        </Card>
      </Box>
      <Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
        <EntityAsOfView entityId={entityId} date={asOfDate} onDateChange={setAsOfDate} />
      </Suspense>
    </Box>
  );
};

export default EntityAsOfSection;
