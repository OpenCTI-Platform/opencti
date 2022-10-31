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
import { QueryRenderer } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { now } from '../../../../utils/Time';
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

const cyioCoreObjectTotalAcceptedRiskCountQuery = graphql`
  query CyioCoreObjectTotalAcceptedRiskCountQuery(
    $type: String
    $field: String!
    $match: [String]
    $operation: StatsOperation
    $endDate: DateTime!
  ) {
    risksCount(
      type: $type
      match: $match
      field: $field
      operation: $operation
      endDate: $endDate
    ) {
      total
      count
    }
  }
`;

class CyioCoreObjectTotalAcceptedRiskCount extends Component {
  renderContent() {
    const {
      t,
      title,
      endDate,
      classes,
    } = this.props;
    const finalEndDate = endDate || now();
    const riskCountVariables = {
      type: 'Risk',
      field: 'accepted', 
      match: ['approved'],
      operation: 'count',
      endDate: finalEndDate,
    };
    return (
      <QueryRenderer
        query={cyioCoreObjectTotalAcceptedRiskCountQuery}
        variables={riskCountVariables}
        render={({ props }) => {
          if (props && props.risksCount) {
            return (
              <Card classes={{ root: classes.card }} variant="outlined">
                <Suspense fallback={<Loader variant="inElement" />}>
                  <CardContent>
                    <div className={classes.title}>
                      {title || t('Total Component')}
                    </div>
                    <div className={classes.content}>
                      <div className={classes.number}>
                        {props.risksCount.total && t(props.risksCount.total)}
                      </div>
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
          if (props) {
            return (
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t('No entities of this type has been found.')}
                </span>
              </div>
            );
          }
          return (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                <CircularProgress size={40} thickness={2} />
              </span>
            </div>
          );
        }}
      />
    );
  }

  render() {
    const {
      t, classes, title, variant, height,
    } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {title || t('Total Active Risks')}
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

CyioCoreObjectTotalAcceptedRiskCount.propTypes = {
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(CyioCoreObjectTotalAcceptedRiskCount);
