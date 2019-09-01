import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import { QueryRenderer } from '../../../relay/environment';
import inject18n from '../../../components/i18n';
import AttributesList, {
  attributesListQuery,
} from './attributes/AttributesList';
import AttributeCreation from './attributes/AttributeCreation';

const styles = () => ({
  paper: {
    minHeight: '100%',
    margin: '3px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

class Attributes extends Component {
  render() {
    const { classes, t } = this.props;
    const argumentsReportClass = { type: 'report_class' };
    const argumentsPlayedRole = { type: 'role_played' };
    return (
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6}>
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ float: 'left' }}
          >
            {t('Report types')}
          </Typography>
          <AttributeCreation
            attributeType="report_class"
            paginationOptions={argumentsReportClass}
          />
          <div className="clearfix" />
          <Paper classes={{ root: classes.paper }} elevation={2}>
            <QueryRenderer
              query={attributesListQuery}
              variables={argumentsReportClass}
              render={({ props }) => {
                if (props) {
                  return (
                    <AttributesList
                      paginationOptions={argumentsReportClass}
                      data={props}
                    />
                  );
                }
                return <div> &nbsp; </div>;
              }}
            />
          </Paper>
        </Grid>
        <Grid item={true} xs={6}>
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ float: 'left' }}
          >
            {t('Played roles of observables')}
          </Typography>
          <AttributeCreation
            attributeType="role_played"
            paginationOptions={argumentsPlayedRole}
          />
          <div className="clearfix" />
          <Paper classes={{ root: classes.paper }} elevation={2}>
            <QueryRenderer
              query={attributesListQuery}
              variables={argumentsPlayedRole}
              render={({ props }) => {
                if (props) {
                  return (
                    <AttributesList
                      paginationOptions={argumentsPlayedRole}
                      data={props}
                    />
                  );
                }
                return <div> &nbsp; </div>;
              }}
            />
          </Paper>
        </Grid>
      </Grid>
    );
  }
}

Attributes.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(Attributes);
