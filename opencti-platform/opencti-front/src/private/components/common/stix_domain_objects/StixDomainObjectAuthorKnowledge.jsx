import React, { useMemo } from 'react';
import * as PropTypes from 'prop-types';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Grid from '@mui/material/Grid';
import { styled, useTheme } from '@mui/material/styles';
import { DescriptionOutlined, DeviceHubOutlined } from '@mui/icons-material';
import { HexagonMultipleOutline } from 'mdi-material-ui';
import Typography from '@mui/material/Typography';
import { Paper } from '@filigran/design-system';
import Chart from '../charts/Chart';
import { QueryRenderer } from '../../../../relay/environment';
import { monthsAgo, now, yearsAgo } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import ItemNumberDifference from '../../../../components/ItemNumberDifference';
import Loader from '../../../../components/Loader';
import { areaChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';
import useTimeSeriesAxisFormatter from '../../../../utils/hooks/useTimeSeriesAxisFormatter';

const cardSx = {
  width: '100%',
  marginBottom: '20px',
  borderRadius: '4px',
  position: 'relative',
};

const Count = styled('div')({
  marginTop: 10,
  float: 'left',
  fontSize: 30,
});

const Title = styled('div')({
  marginTop: 5,
  textTransform: 'uppercase',
  fontSize: 12,
  fontWeight: 500,
  color: '#a8a8a8',
});

const Icon = styled('div')(({ theme }) => ({
  position: 'absolute',
  color: theme.palette.primary.main,
  top: 35,
  right: 20,
}));

const stixDomainObjectAuthorKnowledgeReportsNumberQuery = graphql`
  query StixDomainObjectAuthorKnowledgeReportsNumberQuery(
    $authorId: String
    $endDate: DateTime
  ) {
    reportsNumber(authorId: $authorId, endDate: $endDate) {
      total
      count
    }
  }
`;

const stixDomainObjectAuthorKnowledgeStixCoreRelationshipsNumberQuery = graphql`
  query StixDomainObjectAuthorKnowledgeStixCoreRelationshipsNumberQuery(
    $relationship_type: [String]
    $authorId: String
    $toTypes: [String]
    $endDate: DateTime
  ) {
    stixCoreRelationshipsNumber(
      relationship_type: $relationship_type
      authorId: $authorId
      toTypes: $toTypes
      endDate: $endDate
    ) {
      total
      count
    }
  }
`;

const stixDomainObjectAuthorKnowledgeStixDomainObjectsTimeSeriesQuery = graphql`
  query StixDomainObjectAuthorKnowledgeStixDomainObjectsTimeSeriesQuery(
    $authorId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    stixDomainObjectsTimeSeries(
      authorId: $authorId
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
    ) {
      date
      value
    }
  }
`;

const StixDomainObjectAuthorKnowledge = ({ t, n, stixDomainObjectId }) => {
  const theme = useTheme();
  const timeSeriesAxisFormatter = useTimeSeriesAxisFormatter('month');
  const fallbackDates = useMemo(() => ({
    monthAgo: monthsAgo(1),
    yearAgo: yearsAgo(1),
    end: now(),
  }), []);

  const reportsNumberVariables = useMemo(() => ({
    authorId: stixDomainObjectId,
    endDate: fallbackDates.monthAgo,
  }), [stixDomainObjectId, fallbackDates]);

  const stixCoreRelationshipsObservablesVariables = useMemo(() => ({
    authorId: stixDomainObjectId,
    toTypes: ['Stix-Cyber-Observable'],
    endDate: fallbackDates.monthAgo,
  }), [stixDomainObjectId, fallbackDates]);

  const stixCoreRelationshipsRelationsVariables = useMemo(() => ({
    authorId: stixDomainObjectId,
    endDate: fallbackDates.monthAgo,
  }), [stixDomainObjectId, fallbackDates]);

  const timeSeriesVariables = useMemo(() => ({
    authorId: stixDomainObjectId,
    field: 'created_at',
    operation: 'count',
    startDate: fallbackDates.yearAgo,
    endDate: fallbackDates.end,
    interval: 'month',
  }), [stixDomainObjectId, fallbackDates]);

  return (
    <div>
      <Grid container={true} spacing={3}>
        <Grid size={4}>
          <Card
            variant="outlined"
            sx={cardSx}
            style={{ height: 120 }}
          >
            <QueryRenderer
              query={stixDomainObjectAuthorKnowledgeReportsNumberQuery}
              variables={reportsNumberVariables}
              render={({ props }) => {
                if (props && props.reportsNumber) {
                  const { total } = props.reportsNumber;
                  const difference = total - props.reportsNumber.count;
                  return (
                    <CardContent>
                      <Title>
                        {t('Total reports')}
                      </Title>
                      <Count>{n(total)}</Count>
                      <ItemNumberDifference difference={difference} />
                      <Icon>
                        <DescriptionOutlined
                          color="inherit"
                          fontSize="large"
                        />
                      </Icon>
                    </CardContent>
                  );
                }
                return (
                  <div style={{ textAlign: 'center', paddingTop: 35 }}>
                    <CircularProgress size={40} thickness={2} />
                  </div>
                );
              }}
            />
          </Card>
        </Grid>
        <Grid size={4}>
          <Card
            variant="outlined"
            sx={cardSx}
            style={{ height: 120 }}
          >
            <QueryRenderer
              query={
                stixDomainObjectAuthorKnowledgeStixCoreRelationshipsNumberQuery
              }
              variables={stixCoreRelationshipsObservablesVariables}
              render={({ props }) => {
                if (props && props.stixCoreRelationshipsNumber) {
                  const { total } = props.stixCoreRelationshipsNumber;
                  const difference = total - props.stixCoreRelationshipsNumber.count;
                  return (
                    <CardContent>
                      <Title>
                        {t('Total observables')}
                      </Title>
                      <Count>{n(total)}</Count>
                      <ItemNumberDifference difference={difference} />
                      <Icon>
                        <HexagonMultipleOutline
                          color="inherit"
                          fontSize="large"
                        />
                      </Icon>
                    </CardContent>
                  );
                }
                return (
                  <div style={{ textAlign: 'center', paddingTop: 35 }}>
                    <CircularProgress size={40} thickness={2} />
                  </div>
                );
              }}
            />
          </Card>
        </Grid>
        <Grid size={4}>
          <Card
            variant="outlined"
            sx={cardSx}
            style={{ height: 120 }}
          >
            <QueryRenderer
              query={
                stixDomainObjectAuthorKnowledgeStixCoreRelationshipsNumberQuery
              }
              variables={stixCoreRelationshipsRelationsVariables}
              render={({ props }) => {
                if (props && props.stixCoreRelationshipsNumber) {
                  const { total } = props.stixCoreRelationshipsNumber;
                  const difference = total - props.stixCoreRelationshipsNumber.count;
                  return (
                    <CardContent>
                      <Title>
                        {t('Total relations')}
                      </Title>
                      <Count>{n(total)}</Count>
                      <ItemNumberDifference difference={difference} />
                      <Icon>
                        <DeviceHubOutlined color="inherit" fontSize="large" />
                      </Icon>
                    </CardContent>
                  );
                }
                return (
                  <div style={{ textAlign: 'center', paddingTop: 35 }}>
                    <CircularProgress size={40} thickness={2} />
                  </div>
                );
              }}
            />
          </Card>
        </Grid>
      </Grid>
      <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
        <Grid size={12}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Created entities')}
          </Typography>
          {/* padding 20/20/0/20 -> a uniform 16, arbitrated from a board: 16 and
              not 24, to keep the three asymmetric sites consistent */}
          <Paper
            padding={16}
            style={{ marginTop: 8, height: 300 }}
          >
            <QueryRenderer
              query={
                stixDomainObjectAuthorKnowledgeStixDomainObjectsTimeSeriesQuery
              }
              variables={timeSeriesVariables}
              render={({ props }) => {
                if (props && props.stixDomainObjectsTimeSeries) {
                  const chartData = props.stixDomainObjectsTimeSeries.map(
                    (entry) => ({
                      x: new Date(entry.date),
                      y: entry.value,
                    }),
                  );
                  return (
                    <Chart
                      options={areaChartOptions(
                        theme,
                        true,
                        timeSeriesAxisFormatter,
                        simpleNumberFormat,
                        undefined,
                      )}
                      series={[
                        {
                          name: t('Number of reports'),
                          data: chartData,
                        },
                      ]}
                      type="area"
                      width="100%"
                      height="100%"
                    />
                  );
                }
                return <Loader variant="inElement" />;
              }}
            />
          </Paper>
        </Grid>
      </Grid>
    </div>
  );
};

StixDomainObjectAuthorKnowledge.propTypes = {
  stixDomainObjectId: PropTypes.string,
  stixDomainObjectType: PropTypes.string,
  t: PropTypes.func,
};

export default inject18n(StixDomainObjectAuthorKnowledge);
