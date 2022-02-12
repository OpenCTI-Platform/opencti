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
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  bottomNav: {
    zIndex: 1000,
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
    overflow: 'hidden',
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
      >
        <div
          style={{
            height: 54,
            verticalAlign: 'top',
            transition: 'height 0.2s linear',
          }}
        >
          <div
            style={{
              verticalAlign: 'top',
              width: '100%',
              height: 54,
              paddingTop: 3,
            }}
          >
            <div
              style={{
                float: 'left',
                marginLeft: 200,
                height: '100%',
                display: 'flex',
              }}
            >
              <FormControl style={{ margin: '5px 15px 0 0' }}>
                <InputLabel>{t('Kill chain')}</InputLabel>
                <Select
                  value={currentKillChain}
                  onChange={handleChangeKillChain.bind(this)}
                  style={{ marginTop: 10 }}
                >
                  {killChains.map((killChainName) => (
                    <MenuItem key={killChainName} value={killChainName}>
                      {killChainName}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
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
                    size="large"
                  >
                    <FilterListOutlined />
                  </IconButton>
                </span>
              </Tooltip>
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
                    size="large"
                  >
                    <InvertColorsOffOutlined />
                  </IconButton>
                </span>
              </Tooltip>
            </div>
          </div>
        </div>
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
