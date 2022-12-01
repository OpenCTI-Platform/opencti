import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, assoc } from 'ramda';
import { withTheme, withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Table from '@material-ui/core/Table';
import TableBody from '@material-ui/core/TableBody';
import TableCell from '@material-ui/core/TableCell';
import TableContainer from '@material-ui/core/TableContainer';
import TableRow from '@material-ui/core/TableRow';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { monthsAgo, now } from '../../../../utils/Time';
import {
  dashboardQueryRisksListDistribution,
} from '../../settings/DashboardQuery';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    overflowY: 'auto',
  },
  paper: {
    height: '100%',
    padding: 0,
    borderRadius: 6,
  },
});

class CyioCoreObjectVulnerableInventoryItemList extends Component {
  renderListChartQuery() {
    const { widget, t } = this.props;
    switch (widget.config && widget.config.queryType) {
      case 'riskDistribution':
      case 'risksDistribution':
        return this.renderContent();
      default:
        return (
          <div style={{ display: 'table', height: '100%', width: '100%' }}>
            <span
              style={{
                display: 'table-cell',
                verticalAlign: 'middle',
                textAlign: 'center',
              }}
            >
              {t('Not implemented yet.')}
            </span>
          </div>
        );
    }
  }

  renderContent() {
    const {
      t,
      startDate,
      endDate,
      widget,
      classes,
    } = this.props;
    const {
      operation, type, field,
    } = widget.config.variables;
    const finalStartDate = startDate || monthsAgo(12);
    const finalEndDate = endDate || now();
    const ListChartVariables = {
      type: type || null,
      field: field || null,
      limit: 10,
      operation: operation || 'count',
      startDate: finalStartDate,
      endDate: finalEndDate,
    };
    return (
      <>
        <Typography variant="h4" gutterBottom={true}>
          {widget.config.name || t('Component')}
        </Typography>
        <QueryRenderer
          query={dashboardQueryRisksListDistribution}
          variables={ListChartVariables}
          render={({ props }) => {
            if (props && props.risksDistribution) {
              return (
                <div id="container" className={classes.container}>
                  <TableContainer style={{ overflow: 'hidden' }}>
                    <Table size="small" style={{ width: '100%' }}>
                      <TableBody>
                        {props.risksDistribution.map((list, i) => (
                          <TableRow hover={true} key={i}>
                            <TableCell align="left">
                              {list.label && t(list.label)}
                            </TableCell>
                            <TableCell align="left">
                              {list.value && t(list.value)}
                            </TableCell>
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
      </>
    );
  }

  render() {
    const {
      height,
    } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        {this.renderListChartQuery()}
      </div>
    );
  }
}

CyioCoreObjectVulnerableInventoryItemList.propTypes = {
  title: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  height: PropTypes.number,
  startDate: PropTypes.object,
  endDate: PropTypes.object,
  dateAttribute: PropTypes.string,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(CyioCoreObjectVulnerableInventoryItemList);
