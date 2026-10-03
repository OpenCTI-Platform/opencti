import { useMemo, useState } from 'react';
import { Stack, Typography } from '@mui/material';
import { Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import useConnectedDocumentModifier from '../../../../utils/hooks/useConnectedDocumentModifier';
import DeployedOnRelationships from './DeployedOnRelationships';
import DisseminationAssuranceMetrics from './DisseminationAssuranceMetrics';
import { type Period, periodStartDate } from './disseminationAssuranceUtils';

const DisseminationAssuranceOverview = () => {
  const { t_i18n } = useFormatter();
  const { setTitle } = useConnectedDocumentModifier();
  setTitle(t_i18n('Dissemination assurance | Defense'));
  const [period, setPeriod] = useState<Period>('all');
  const startDate = useMemo(() => periodStartDate(period), [period]);
  return (
    <Stack gap={3} data-testid="dissemination-assurance-overview-page">
      <Stack direction="row" alignItems="flex-end" justifyContent="space-between" gap={2}>
        <Typography variant="body2" color="text.secondary" sx={{ maxWidth: 820 }}>
          {t_i18n('Disseminated is not deployed, deployed is not proven. Stream connectors report where each indicator is live, OpenAEV proves that security platforms detect or prevent it.')}
        </Typography>
        <div style={{ minWidth: 200 }}>
          <Select value={period} onValueChange={(value: string) => setPeriod(value as Period)}>
            <SelectLabel>{t_i18n('Period')}</SelectLabel>
            <SelectTrigger aria-label={t_i18n('Period')}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent aria-label={t_i18n('Period')}>
              <SelectItem value="all">{t_i18n('All time')}</SelectItem>
              <SelectItem value="7d">{t_i18n('Last 7 days')}</SelectItem>
              <SelectItem value="30d">{t_i18n('Last 30 days')}</SelectItem>
              <SelectItem value="90d">{t_i18n('Last 90 days')}</SelectItem>
              <SelectItem value="1y">{t_i18n('Last year')}</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </Stack>
      <DisseminationAssuranceMetrics
        startDate={startDate}
        renderDeployments={(kpiFilters) => <DeployedOnRelationships side="all" kpiFilters={kpiFilters} startDate={startDate} />}
      />
    </Stack>
  );
};

export default DisseminationAssuranceOverview;
