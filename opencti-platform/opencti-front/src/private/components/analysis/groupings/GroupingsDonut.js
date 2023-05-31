import React from 'react';
import { graphql } from 'react-relay';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import * as R from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import Chart from '../../common/charts/Chart';
import { QueryRenderer } from '../../../../relay/environment';
import { donutChartOptions } from '../../../../utils/Charts';

const useStyles = makeStyles(() => ({
  paper: {
    height: 300,
    minHeight: 300,
    maxHeight: 300,
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
}));

const groupingsDonutDistributionQuery = graphql`
  query GroupingsDonutDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $limit: Int
    $startDate: DateTime
    $endDate: DateTime
  ) {
    groupingsDistribution(
      field: $field
      operation: $operation
      limit: $limit
      startDate: $startDate
      endDate: $endDate
    ) {
      label
      value
      entity {
        ... on Identity {
          name
        }
      }
    }
  }
`;

const GroupingsDonut = (props) => {
  const { t, field, startDate, endDate, theme, height, title, variant } = props;
  const classes = useStyles();
  const renderContent = () => {
    const groupingsDistributionVariables = {
      field: field || 'grouping_types',
      operation: 'count',
      limit: 8,
      startDate,
      endDate,
    };
    return (
      <QueryRenderer
        query={groupingsDonutDistributionQuery}
        variables={groupingsDistributionVariables}
        render={({ props: resultProps }) => {
          if (
            resultProps
            && resultProps.groupingsDistribution
            && resultProps.groupingsDistribution.length > 0
          ) {
            let data = resultProps.groupingsDistribution;
            if (field && field.includes('internal_id')) {
              data = R.map(
                (n) => R.assoc('label', n.entity.name, n),
                resultProps.groupingsDistribution,
              );
            }
            const chartData = data.map((n) => n.value);
            const labels = data.map((n) => n.label);
            return (
              <Chart
                options={donutChartOptions(theme, labels)}
                series={chartData}
                type="donut"
                width="100%"
                height="100%"
              />
            );
          }
          if (props) {
            return (
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t('No entities of this type has been found.')}
                </span>
              </div>
            );
          }
          return (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                <CircularProgress size={40} thickness={2} />
              </span>
            </div>
          );
        }}
      />
    );
  };
  return (
    <div style={{ height: height || '100%' }}>
      <Typography
        variant="h4"
        gutterBottom={true}
        style={{
          margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
        }}
      >
        {title || t('Groupings distribution')}
      </Typography>
      {variant !== 'inLine' ? (
        <Paper classes={{ root: classes.paper }} variant="outlined">
          {renderContent()}
        </Paper>
      ) : (
        renderContent()
      )}
    </div>
  );
};

export default GroupingsDonut;
