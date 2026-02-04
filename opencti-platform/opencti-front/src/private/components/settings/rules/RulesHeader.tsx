import { graphql, useFragment } from 'react-relay';
import { Grid2 as Grid } from '@mui/material';
import { AutoFix, Database, GraphOutline } from 'mdi-material-ui';
import { useTheme } from '@mui/material/styles';
import { SettingsSuggestOutlined } from '@mui/icons-material';
import Chart from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import { RULES_LOCAL_STORAGE_KEY } from './rules-utils';
import { RulesHeader_data$key } from './__generated__/RulesHeader_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import type { Theme } from '../../../../components/Theme';
import ItemBoolean from '../../../../components/ItemBoolean';
import { parse } from '../../../../utils/Time';
import { areaChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import useAuth from '../../../../utils/hooks/useAuth';
import Card from '../../../../components/common/card/Card';
import CardNumber from '../../../../components/common/card/CardNumber';
import CardStatistic from '../../../../components/common/card/CardStatistic';

const fragmentData = graphql`
  fragment RulesHeader_data on Query 
  @argumentDefinitions(
    startDate: { type: "DateTime!" }
    endDate: { type: "DateTime" }
  ) {
    stixDomainObjectsTimeSeries(
      field: "created_at"
      types: ["Stix-Object"]
      operation: count
      startDate: $startDate
      interval: "month"
      onlyInferred: true
    ) {
      date
      value
    }
    stixRelationshipsTimeSeries(
      field: "created_at"
      relationship_type: ["stix-relationship"]
      operation: count
      startDate: $startDate
      interval: "month"
      onlyInferred: true
    ) {
      date
      value
    }
    stixDomainObjectsNumber(
      types: ["Stix-Object"]
      onlyInferred: true
      endDate: $endDate
    ) {
      total
      count
    }
    stixRelationshipsNumber(
      relationship_type: ["stix-relationship"]
      onlyInferred: true
      endDate: $endDate
    ) {
      total
      count
    }
    ruleManagerInfo {
      lastEventId
    }
  }
`;

interface RulesHeaderProps {
  data: RulesHeader_data$key;
}

const RulesHeader = ({ data }: RulesHeaderProps) => {
  const theme = useTheme<Theme>();
  const { platformModuleHelpers } = useAuth();
  const { t_i18n, nsdt, md } = useFormatter();
  const { viewStorage, helpers } = usePaginationLocalStorage(RULES_LOCAL_STORAGE_KEY, {});

  const {
    stixDomainObjectsTimeSeries,
    stixRelationshipsTimeSeries,
    stixDomainObjectsNumber,
    stixRelationshipsNumber,
    ruleManagerInfo,
  } = useFragment(fragmentData, data);

  const totalRelations = stixRelationshipsNumber?.total ?? 0;
  const differenceRelations = totalRelations - (stixRelationshipsNumber?.count ?? 0);
  const totalEntities = stixDomainObjectsNumber?.total ?? 0;
  const differenceEntities = totalEntities - (stixDomainObjectsNumber?.count ?? 0);
  const isEngineEnabled = platformModuleHelpers.isRuleEngineEnable();
  const lastEventTimestamp = parseInt((ruleManagerInfo?.lastEventId ?? '-').split('-')[0], 10);

  const chartDataEntities = (stixDomainObjectsTimeSeries ?? []).flatMap((entry) => {
    if (!entry) return [];
    const date = new Date(entry.date);
    date.setDate(date.getDate() + 15);
    return {
      x: date,
      y: entry.value,
    };
  });
  const chartDataRelations = (stixRelationshipsTimeSeries ?? []).flatMap((entry) => {
    if (!entry) return [];
    const date = new Date(entry.date);
    date.setDate(date.getDate() + 15);
    return {
      x: date,
      y: entry.value,
    };
  });

  return (
    <>
      <SearchInput
        variant="small"
        onSubmit={helpers.handleSearch}
        keyword={viewStorage.searchTerm ?? ''}
        style={{ marginBottom: theme.spacing(3) }}
      />
      <Grid container spacing={3}>
        <Grid size={{ xs: 6 }} container spacing={3}>
          <Grid size={{ xs: 6 }}>
            <CardNumber
              value={totalEntities}
              diffValue={differenceEntities}
              diffLabel={t_i18n('24 hours')}
              label={t_i18n('Total inferred entities')}
              icon={(
                <Database
                  sx={{ opacity: 0.35 }}
                  fontSize="large"
                />
              )}
            />
          </Grid>
          <Grid size={{ xs: 6 }}>
            <CardNumber
              value={totalRelations}
              diffValue={differenceRelations}
              diffLabel={t_i18n('24 hours')}
              label={t_i18n('Total inferred relations')}
              icon={(
                <GraphOutline
                  sx={{ opacity: 0.35 }}
                  fontSize="large"
                />
              )}
            />
          </Grid>
          <Grid size={{ xs: 6 }}>
            <CardStatistic
              label={t_i18n('Rules engine status')}
              icon={(
                <AutoFix
                  sx={{ opacity: 0.35 }}
                  fontSize="large"
                />
              )}
              value={(
                <ItemBoolean
                  status={isEngineEnabled}
                  label={isEngineEnabled ? t_i18n('Enabled') : t_i18n('Disabled')}
                />
              )}
            />
          </Grid>
          <Grid size={{ xs: 6 }}>
            <CardStatistic
              label={t_i18n('Last event processed')}
              icon={(
                <SettingsSuggestOutlined
                  sx={{ opacity: 0.35 }}
                  fontSize="large"
                />
              )}
              value={(
                <div style={{ fontSize: 18 }}>
                  {nsdt(parse(lastEventTimestamp))}
                </div>
              )}
            />
          </Grid>
        </Grid>
        <Grid size={{ xs: 6 }}>
          <Card padding="none" title={t_i18n('Inferred entities')}>
            <Chart
              type="area"
              width="100%"
              height={200}
              options={areaChartOptions(
                theme,
                true,
                md,
                simpleNumberFormat,
                'dataPoints',
              ) as ApexOptions}
              series={[
                { name: t_i18n('Inferred entities'), data: chartDataEntities },
                { name: t_i18n('Inferred relationships'), data: chartDataRelations },
              ]}
            />
          </Card>
        </Grid>
      </Grid>
    </>
  );
};

export default RulesHeader;
