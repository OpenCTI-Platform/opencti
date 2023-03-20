import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import FiberManualRecordIcon from '@material-ui/icons/FiberManualRecord';
import IconButton from '@material-ui/core/IconButton';
import Tooltip from '@material-ui/core/Tooltip';
import { withStyles } from '@material-ui/core/styles';
import { compose } from 'ramda';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  iconButton: {
    padding: 0,
    minWidth: '1rem',
  },
  veryHigh: {
    fill: theme.palette.riskPriority.veryHigh,
  },
  high: {
    fill: theme.palette.riskPriority.high,
  },
  moderate: {
    fill: theme.palette.riskPriority.moderate,
  },
  low: {
    fill: theme.palette.riskPriority.low,
  },
  veryLow: {
    fill: theme.palette.riskPriority.veryLow,
  },
});

const RiskTooltip = withStyles((theme) => ({
  tooltip: {
    backgroundColor: 'rgba(241, 241, 242, 0.25)',
    color: '#FFF',
    maxWidth: 220,
    fontSize: theme.typography.pxToRem(12),
    border: '1px solid rgba(241, 241, 242, 0.5)',
    borderRadius: '4px',
  },
}))(Tooltip);

class RiskLevel extends Component {
  render() {
    const { risk, t, classes } = this.props;
    if (risk === 'very_high') {
      return Array.from({ length: 5 },
        (item, index) => <RiskTooltip
          title={risk && t('Very High')}><IconButton className={classes.iconButton} key={index}><FiberManualRecordIcon className={classes.veryHigh} /></IconButton></RiskTooltip>);
    }
    if (risk === 'high') {
      return Array.from({ length: 4 },
        (item, index) => <RiskTooltip
          title={risk && t('High')}><IconButton className={classes.iconButton} key={index}><FiberManualRecordIcon className={classes.high} /></IconButton></RiskTooltip>);
    }
    if (risk === 'moderate') {
      return Array.from({ length: 3 },
        (item, index) => <RiskTooltip
          title={risk && t('Moderate')}><IconButton className={classes.iconButton} key={index}><FiberManualRecordIcon className={classes.moderate} /></IconButton></RiskTooltip>);
    }
    if (risk === 'low') {
      return Array.from({ length: 2 },
        (item, index) => <RiskTooltip
          title={risk && t('Low')}><IconButton className={classes.iconButton} key={index}><FiberManualRecordIcon className={classes.low} /></IconButton></RiskTooltip>);
    }
    if (risk === 'very_low') {
      return Array.from({ length: 1 },
        (item, index) => <RiskTooltip
          title={risk && t('Very Low')}><IconButton className={classes.iconButton} key={index}><FiberManualRecordIcon className={classes.veryLow} /></IconButton></RiskTooltip>);
    }
    if (risk === 'fips_199_high') {
      return Array.from({ length: 1 },
        (item, index) => <RiskTooltip
          title={risk && t('High')}><IconButton className={classes.iconButton} key={index}><FiberManualRecordIcon className={classes.veryHigh} /></IconButton></RiskTooltip>);
    }
    if (risk === 'fips_199_moderate') {
      return Array.from({ length: 1 },
        (item, index) => <RiskTooltip
          title={risk && t('Moderate')}><IconButton className={classes.iconButton} key={index}><FiberManualRecordIcon className={classes.high} /></IconButton></RiskTooltip>);
    }
    if (risk === 'fips_199_low') {
      return Array.from({ length: 1 },
        (item, index) => <RiskTooltip
          title={risk && t('Low')}><IconButton className={classes.iconButton} key={index}><FiberManualRecordIcon className={classes.low} /></IconButton></RiskTooltip>);
    }
    return <></>;
  }
}

RiskLevel.propTypes = {
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
};

export default compose(inject18n, withStyles(styles))(RiskLevel);
