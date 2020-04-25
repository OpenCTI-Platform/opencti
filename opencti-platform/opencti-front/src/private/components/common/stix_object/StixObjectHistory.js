import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core';
import inject18n from '../../../../components/i18n';
import StixObjectHistoryLines, {
  stixObjectHistoryLinesQuery,
} from './StixObjectHistoryLines';
import { QueryRenderer } from '../../../../relay/environment';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

class StixObjectHistory extends Component {
  render() {
    const { classes, t, entityId } = this.props;
    return (
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Entity')}
          </Typography>
          <QueryRenderer
            query={stixObjectHistoryLinesQuery}
            variables={{
              filters: [
                { key: 'event_entity_id', values: [entityId] },
                { key: 'event_type', values: ['create', 'update'] },
              ],
              first: 200,
              orderBy: 'event_date',
              orderMode: 'desc',
            }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixObjectHistoryLines
                    entityId={entityId}
                    data={props}
                    isRelationLog={false}
                  />
                );
              }
              return <div />;
            }}
          />
        </Grid>
        <Grid item={true} xs={6}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Relations of the entity')}
          </Typography>
          <QueryRenderer
            query={stixObjectHistoryLinesQuery}
            variables={{
              filters: [
                { key: 'event_entity_id', values: [entityId] },
                {
                  key: 'event_type',
                  values: ['add_relation', 'remove_relation'],
                },
              ],
              first: 200,
              orderBy: 'event_date',
              orderMode: 'desc',
            }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixObjectHistoryLines
                    entityId={entityId}
                    data={props}
                    isRelationLog={true}
                  />
                );
              }
              return <div />;
            }}
          />
        </Grid>
      </Grid>
    );
  }
}

StixObjectHistory.propTypes = {
  t: PropTypes.func,
  entityId: PropTypes.string,
};

export default compose(inject18n, withStyles(styles))(StixObjectHistory);
