import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import inject18n from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import { attributesQuery } from '../settings/attributes/AttributesLines';

const styles = (theme) => ({
  button: {
    marginRight: theme.spacing(1),
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    textTransform: 'none',
  },
});

class TopMenuReports extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/reports/all"
          variant={
            location.pathname === '/dashboard/reports/all'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/reports/all'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('All reports')}
        </Button>
        <QueryRenderer
          query={attributesQuery}
          variables={{ type: 'report_class' }}
          render={({ props }) => {
            if (props && props.attributes) {
              const reportClassesEdges = props.attributes.edges;
              return reportClassesEdges.map((reportClassEdge) => {
                const uri = reportClassEdge.node.value.replace(/\s/g, '_');
                return (
                  <Button
                    key={uri}
                    component={Link}
                    to={`/dashboard/reports/${uri}`}
                    variant={
                      location.pathname === `/dashboard/reports/${uri}`
                        ? 'contained'
                        : 'text'
                    }
                    size="small"
                    color={
                      location.pathname === `/dashboard/reports/${uri}`
                        ? 'primary'
                        : 'inherit'
                    }
                    classes={{ root: classes.button }}
                  >
                    {reportClassEdge.node.value}
                  </Button>
                );
              });
            }
            return <span>&nbsp;</span>;
          }}
        />
        <Button
          component={Link}
          to="/dashboard/reports/references"
          variant={
            location.pathname === '/dashboard/reports/references'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/reports/references'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('References')}
        </Button>
      </div>
    );
  }
}

TopMenuReports.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuReports);
