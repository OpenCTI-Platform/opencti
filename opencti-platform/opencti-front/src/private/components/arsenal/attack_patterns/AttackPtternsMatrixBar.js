import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import {
  FilterListOutlined,
  InvertColorsOffOutlined,
} from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Slide from '@mui/material/Slide';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import Grid from '@mui/material/Grid';
import inject18n from '../../../../components/i18n';

const styles = () => ({
  bottomNav: {
    zIndex: 1000,
    padding: '10px 200px 10px 205px',
    display: 'flex',
  },
  divider: {
    display: 'inline-block',
    verticalAlign: 'middle',
    height: '100%',
    margin: '0 5px 0 5px',
  },
});

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

class AttackPtternsMatrixBar extends Component {
  render() {
    const {
      t,
      classes,
      currentModeOnlyActive,
      currentColorsReversed,
      currentKillChain,
      handleChangeKillChain,
      handleToggleModeOnlyActive,
      handleToggleColorsReversed,
      killChains,
    } = this.props;
    return (
      <Drawer
        anchor="bottom"
        variant="permanent"
        classes={{ paper: classes.bottomNav }}
        PaperProps={{ variant: 'elevation', elevation: 1 }}
      >
        <Grid container={true} spacing={1}>
          <Grid item={true} xs="auto">
            <Select
              size="small"
              value={currentKillChain}
              onChange={handleChangeKillChain.bind(this)}
            >
              {killChains.map((killChainName) => (
                <MenuItem key={killChainName} value={killChainName}>
                  {killChainName}
                </MenuItem>
              ))}
            </Select>
          </Grid>
          <Grid item={true} xs="auto">
            <Tooltip
              title={
                currentModeOnlyActive
                  ? t('Display the whole matrix')
                  : t('Display only used techniques')
              }
            >
              <span>
                <IconButton
                  color={currentModeOnlyActive ? 'secondary' : 'primary'}
                  onClick={handleToggleModeOnlyActive.bind(this)}
                  size="small"
                >
                  <FilterListOutlined />
                </IconButton>
              </span>
            </Tooltip>
          </Grid>
          <Grid item={true} xs="auto">
            <Tooltip
              title={
                currentColorsReversed
                  ? t('Disable invert colors')
                  : t('Enable invert colors')
              }
            >
              <span>
                <IconButton
                  color={currentColorsReversed ? 'secondary' : 'primary'}
                  onClick={handleToggleColorsReversed.bind(this)}
                  size="small"
                >
                  <InvertColorsOffOutlined />
                </IconButton>
              </span>
            </Tooltip>
          </Grid>
        </Grid>
      </Drawer>
    );
  }
}

AttackPtternsMatrixBar.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  currentModeOnlyActive: PropTypes.bool,
  handleToggleModeOnlyActive: PropTypes.func,
  currentColorsReversed: PropTypes.bool,
  handleToggleColorsReversed: PropTypes.func,
  currentKillChain: PropTypes.string,
  handleChangeKillChain: PropTypes.func,
  killChains: PropTypes.array,
};

export default R.compose(inject18n, withStyles(styles))(AttackPtternsMatrixBar);
