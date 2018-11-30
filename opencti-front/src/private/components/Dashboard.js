import React, {Component} from 'react';
import {withStyles} from '@material-ui/core/styles';
import * as PropTypes from 'prop-types';
import {compose} from 'ramda';
import Card from '@material-ui/core/Card';
import CardHeader from '@material-ui/core/CardHeader';
import CardContent from '@material-ui/core/CardContent';
import inject18n from '../../components/i18n';

const styles = () => ({
  title: {

  }
});

class Dashboard extends Component {
  render() {
    const {t, classes} = this.props;
    return (
      <div>
        <Card raised={true}>
            <CardContent>
              <div className={classes.title}>
                {t('Total entities')}
              </div>
              <div className={classes.icon}>

              </div>
            </CardContent>
        </Card>
      </div>
    );
  }
}

Dashboard.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Dashboard);
