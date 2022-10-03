import React, { Component, Suspense } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles, withTheme } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import {
  Card, CardContent, ListItemIcon, SvgIcon,
} from '@material-ui/core';
import AccountBalanceIcon from '@material-ui/icons/AccountBalance';
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { monthsAgo, now, numberOfDays } from '../../../../utils/Time';
import ItemNumberDifference from '../../../../components/ItemNumberDifference';
import Loader from '../../../../components/Loader';

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
    marginTop: '1rem',
    float: 'left',
    fontSize: '1.5rem',
    height: 'inherit',
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
    display: 'flex',
    justifyContent: 'flex-end',
    height: 'inherit',
  },
});
class CyioCoreObjectTotalComponentsCount extends Component {
  renderContent() {
    const { t, n, classes } = this.props;
    return (
      <Card classes={{ root: classes.card }} variant="outlined">
        <Suspense fallback={<Loader variant="inElement" />}>
          <CardContent>
            <div className={classes.title}>{t('Total Inventory Items')}</div>
            <div className={classes.content}>
              <div className={classes.number}>{n('10')}</div>
            </div>
            <div className={classes.icon}>
              <ListItemIcon style={{ minWidth: 35 }}>
                <SvgIcon style={{ fontSize: '2rem' }}>
                  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="#ffffff" d="M12 4.942c1.827 1.105 3.474 1.6 5 1.833v7.76c0 1.606-.415 1.935-5 4.76v-14.353zm9-1.942v11.535c0 4.603-3.203 5.804-9 9.465-5.797-3.661-9-4.862-9-9.465v-11.535c3.516 0 5.629-.134 9-3 3.371 2.866 5.484 3 9 3zm-2 1.96c-2.446-.124-4.5-.611-7-2.416-2.5 1.805-4.554 2.292-7 2.416v9.575c0 3.042 1.69 3.83 7 7.107 5.313-3.281 7-4.065 7-7.107v-9.575z" /></svg>
                </SvgIcon>
              </ListItemIcon>
            </div>
          </CardContent>
        </Suspense>
      </Card>
    );
  }

  render() {
    const {
      t, classes, title, variant, height,
    } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {title || t('Total Inventory Items')}
        </Typography>
        {variant === 'inLine' ? (
          this.renderContent()
        ) : (
          <Paper classes={{ root: classes.paper }} elevation={2}>
            {this.renderContent()}
          </Paper>
        )}
      </div>
    );
  }
}

CyioCoreObjectTotalComponentsCount.propTypes = {
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(CyioCoreObjectTotalComponentsCount);
