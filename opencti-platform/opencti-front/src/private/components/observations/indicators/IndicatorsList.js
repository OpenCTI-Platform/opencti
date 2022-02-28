import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    overflow: 'auto',
    paddingBottom: 10,
  },
  paper: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

const indicatorsListDistributionQuery = graphql`
  query IndicatorsListDistributionQuery(
    $field: String!
    $operation: StatsOperation!
    $limit: Int
    $startDate: DateTime
    $endDate: DateTime
  ) {
    indicatorsDistribution(
      field: $field
      operation: $operation
      limit: $limit
      startDate: $startDate
      endDate: $endDate
    ) {
      label
      value
      entity {
        ... on Indicator {
          revoked
          pattern_type
        }
      }
    }
  }
`;

class IndicatorsList extends Component {
  renderContent() {
    const { t, field, startDate, endDate, classes } = this.props;
    const indicatorsDistributionVariables = {
      field: field || 'pattern_type',
      operation: 'count',
      limit: 8,
      startDate,
      endDate,
    };
    return (
      <QueryRenderer
        query={indicatorsListDistributionQuery}
        variables={indicatorsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.indicatorsDistribution
            && props.indicatorsDistribution.length > 0
          ) {
            const data = props.indicatorsDistribution;
            return (
              <div id="container" className={classes.container}>
                <TableContainer>
                  <Table size="small" style={{ width: '100%' }}>
                    <TableHead>
                      <TableRow>
                        <TableCell style={{ width: 50 }} align="center">
                          {' '}
                          #{' '}
                        </TableCell>
                        <TableCell>{t('Entity')}</TableCell>
                        <TableCell align="right">{t('Number')}</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {data.map((row) => (
                        <TableRow key={row.label}>
                          <TableCell align="center" style={{ width: 50 }}>
                            <ItemIcon type="Indicator" />
                          </TableCell>
                          <TableCell align="left">{row.label}</TableCell>
                          <TableCell align="right">{row.value}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </div>
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
  }

  render() {
    const { t, classes, title, variant, height } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{
            margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
          }}
        >
          {title || t('Indicators distribution')}
        </Typography>
        {variant !== 'inLine' ? (
          <Paper classes={{ root: classes.paper }} variant="outlined">
            {this.renderContent()}
          </Paper>
        ) : (
          this.renderContent()
        )}
      </div>
    );
  }
}

IndicatorsList.propTypes = {
  relationshipType: PropTypes.string,
  toTypes: PropTypes.array,
  title: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  height: PropTypes.number,
  startDate: PropTypes.object,
  endDate: PropTypes.object,
  dateAttribute: PropTypes.string,
  variant: PropTypes.string,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(IndicatorsList);
