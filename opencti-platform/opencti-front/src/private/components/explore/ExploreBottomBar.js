import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Grid from '@material-ui/core/Grid';
import Button from '@material-ui/core/Button';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Switch from '@material-ui/core/Switch';
import Drawer from '@material-ui/core/Drawer';
import { Clear } from '@material-ui/icons';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 84px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
  },
  icon: {
    marginRight: theme.spacing(1),
    fontSize: 20,
  },
});

class ExploreBottomBar extends Component {
  render() {
    const {
      t,
      classes,
      handleClear,
      inferred,
      handleChangeInferred,
      entityId,
    } = this.props;
    return (
      <Drawer
        anchor="bottom"
        variant="permanent"
        classes={{ paper: classes.bottomNav }}
      >
        <Grid item={true} xs="auto">
          <FormControlLabel
            style={{ paddingTop: 5, marginRight: 15 }}
            control={
              <Switch
                disabled={!entityId}
                checked={inferred}
                onChange={handleChangeInferred.bind(this)}
                color="primary"
              />
            }
            label={t('Inferences')}
          />
        </Grid>
        <div
          style={{
            position: 'absolute',
            top: 25,
            right: 285,
            color: '#ffffff',
          }}
        >
          <Button
            variant="contained"
            size="small"
            className={classes.button}
            onClick={handleClear.bind(this)}
            disabled={!entityId}
          >
            <Clear className={classes.icon} />
            {t('Close')}
          </Button>
        </div>
      </Drawer>
    );
  }
}

ExploreBottomBar.propTypes = {
  entityId: PropTypes.string,
  handleClear: PropTypes.func,
  inferred: PropTypes.bool,
  handleChangeInferred: PropTypes.func,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(ExploreBottomBar);
