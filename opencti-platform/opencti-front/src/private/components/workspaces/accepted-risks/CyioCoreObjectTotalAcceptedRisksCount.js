import React, { Component, Suspense } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles, withTheme } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { Card, CardContent, ListItemIcon } from '@material-ui/core';
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
    borderRadius: 6,
  },
  number: {
    marginTop: 10,
    float: 'left',
    fontSize: 30,
  },
  title: {
    marginTop: 5,
    textTransform: 'uppercase',
    fontSize: 12,
    fontWeight: 500,
    color: theme.palette.text.secondary,
  },
  icon: {
    color: theme.palette.primary.main,
    width: 'auto',
    display: 'flex',
    justifyContent: 'flex-end',
  },
});
class CyioCoreObjectTotalAcceptedRisksCount extends Component {
  renderContent() {
    const {
      t, n, classes,
    } = this.props;
    return (
      <Card
        classes={{ root: classes.card }}
        variant="outlined"
      >
        <Suspense fallback={<Loader variant="inElement" />}>
          <CardContent>
            <div className={classes.title}>{t('Total Accepted Risks')}</div>
            <div className={classes.number}>{n('10')}</div>
            <ItemNumberDifference
              difference={500}
              description={t('24 hours')}
            />
            <div className={classes.icon}>
              <ListItemIcon style={{ minWidth: 35 }}>
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                >
                  <path
                    fill="#ffffff"
                    d="M18.905 14c-2.029 2.401-4.862 5.005-7.905 8-5.893-5.8-11-10.134-11-14.371 0-6.154 8.114-7.587 11-2.676 2.865-4.875 11-3.499 11 2.676 0 .784-.175 1.572-.497 2.371h-6.278c-.253 0-.486.137-.61.358l-.813 1.45-2.27-4.437c-.112-.219-.331-.364-.576-.38-.246-.016-.482.097-.622.299l-1.88 2.71h-1.227c-.346-.598-.992-1-1.732-1-1.103 0-2 .896-2 2s.897 2 2 2c.74 0 1.386-.402 1.732-1h1.956c.228 0 .441-.111.573-.297l.989-1.406 2.256 4.559c.114.229.343.379.598.389.256.011.496-.118.629-.337l1.759-2.908h8.013v2h-5.095z"
                  />
                </svg>
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
          {title || t('Total Accepted Risks')}
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

CyioCoreObjectTotalAcceptedRisksCount.propTypes = {
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(CyioCoreObjectTotalAcceptedRisksCount);
