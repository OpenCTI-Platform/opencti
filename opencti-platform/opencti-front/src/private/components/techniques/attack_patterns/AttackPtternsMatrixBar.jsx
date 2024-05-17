import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import { FilterListOutlined, InvertColorsOffOutlined } from '@mui/icons-material';
import Drawer from '@mui/material/Drawer';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import inject18n from '../../../../components/i18n';
import { UserContext } from '../../../../utils/hooks/useAuth';

const styles = () => ({
  bottomNav: {
    zIndex: 1,
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
      navOpen,
    } = this.props;
    return (
      <UserContext.Consumer>
        {({ bannerSettings }) => (
          <Drawer
            anchor="bottom"
            variant="permanent"
            classes={{ paper: classes.bottomNav }}
            PaperProps={{
              variant: 'elevation',
              elevation: 1,
              style: {
                paddingLeft: navOpen ? 190 : 70,
                bottom: bannerSettings.bannerHeightNumber,
              },
            }}
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
                    margin: '7px 10px 0 0',
                    display: 'flex',
                  }}
                >
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
                </div>
                <div
                  style={{
                    float: 'left',
                    margin: '0 10px 0 10px',
                    display: 'flex',
                  }}
                >
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
        )}
      </UserContext.Consumer>
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
