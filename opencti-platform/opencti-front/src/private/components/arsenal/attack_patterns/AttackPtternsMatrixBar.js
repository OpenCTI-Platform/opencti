import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import IconButton from '@material-ui/core/IconButton';
import Tooltip from '@material-ui/core/Tooltip';
import { FilterListOutlined } from '@material-ui/icons';
import Drawer from '@material-ui/core/Drawer';
import Slide from '@material-ui/core/Slide';
import Select from '@material-ui/core/Select';
import MenuItem from '@material-ui/core/MenuItem';
import FormControl from '@material-ui/core/FormControl';
import InputLabel from '@material-ui/core/InputLabel';
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
      currentKillChain,
      handleChangeKillChain,
      handleToggleModeOnlyActive,
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
                  >
                    <FilterListOutlined />
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
  currentKillChain: PropTypes.string,
  handleChangeKillChain: PropTypes.func,
  killChains: PropTypes.array,
};

export default R.compose(inject18n, withStyles(styles))(AttackPtternsMatrixBar);
