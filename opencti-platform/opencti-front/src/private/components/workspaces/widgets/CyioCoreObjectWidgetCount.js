import React, { Component, Suspense } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles, withTheme } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Typography from '@material-ui/core/Typography';
import {
  Card, CardContent, ListItemIcon,
} from '@material-ui/core';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { now } from '../../../../utils/Time';
import Loader from '../../../../components/Loader';
import {
  dashboardQueryAssetsCount,
  dashboardQueryRisksCount,
} from '../../settings/DashboardQuery';
import ItemIcon from '../../../../components/ItemIcon';

const styles = (theme) => ({
  paper: {
    height: '100%',
    borderRadius: 6,
  },
  chip: {
    fontSize: 10,
    height: 20,
    marginLeft: 10,
  },
  card: {
    width: '100%',
    height: 'inherit',
    borderRadius: 6,
    display: 'grid',
    alignItems: 'center',
    border: 'none',
  },
  number: {
    fontSize: '55px',
  },
  content: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: '0.8rem',
    fontWeight: 500,
    color: theme.palette.text.secondary,
    height: 'inherit',
  },
  icon: {
    color: theme.palette.primary.main,
    width: 'auto',
  },
});

class CyioCoreObjectWidgetRiskCount extends Component {
  renderCountChartQuery() {
    const { widget, t } = this.props;
    switch (widget.config && widget.config.queryType) {
      case 'assetsCount':
        return this.renderAssetChart('asset');
      case 'risksCount':
        return this.renderRiskChart('risk');
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

  renderAssetChart(itemIcon) {
    const {
      t,
      widget,
      endDate,
      classes,
    } = this.props;
    const finalEndDate = endDate || now();
    const countChartVariables = {
      ...widget.config.variables,
      endDate: new Date(finalEndDate).toISOString(),
    };
    return (
      <>
        <Typography variant="h4" gutterBottom={true}>
          {widget.config.name || t('Component')}
        </Typography>
        <QueryRenderer
          query={dashboardQueryAssetsCount}
          variables={countChartVariables}
          render={({ props }) => {
            if (props && props[widget.config.queryType]) {
              return (
                <Card classes={{ root: classes.card }} variant="outlined">
                  <Suspense fallback={<Loader variant="inElement" />}>
                    <CardContent className={ classes.content }>
                        <div className={classes.number}>
                          {props[widget.config.queryType].total
                            && t(props[widget.config.queryType].total)}
                        </div>
                      <div className={classes.icon}>
                        <ListItemIcon style={{ minWidth: 35 }}>
                          <ItemIcon type={itemIcon} />
                        </ListItemIcon>
                      </div>
                    </CardContent>
                  </Suspense>
                </Card>
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

  renderRiskChart(itemIcon) {
    const {
      t,
      widget,
      endDate,
      classes,
    } = this.props;
    const finalEndDate = endDate || now();
    const countChartVariables = {
      ...widget.config.variables,
      endDate: new Date(finalEndDate).toISOString(),
    };
    return (
      <>
        <Typography variant="h4" gutterBottom={true}>
          {widget.config.name || t('Component')}
        </Typography>
        <QueryRenderer
          query={dashboardQueryRisksCount}
          variables={countChartVariables}
          render={({ props }) => {
            if (props && props[widget.config.queryType]) {
              return (
                <Card classes={{ root: classes.card }} variant="outlined">
                  <Suspense fallback={<Loader variant="inElement" />}>
                    <CardContent className={ classes.content }>
                        <div className={classes.number}>
                          {props[widget.config.queryType].total
                            && t(props[widget.config.queryType].total)}
                        </div>
                      <div className={classes.icon}>
                        <ListItemIcon style={{ minWidth: 35 }}>
                          <ItemIcon type={itemIcon} />
                        </ListItemIcon>
                      </div>
                    </CardContent>
                  </Suspense>
                </Card>
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
        {this.renderCountChartQuery()}
      </div>
    );
  }
}

CyioCoreObjectWidgetRiskCount.propTypes = {
  classes: PropTypes.object,
  theme: PropTypes.object,
  widget: PropTypes.object,
  t: PropTypes.func,
  md: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(CyioCoreObjectWidgetRiskCount);
