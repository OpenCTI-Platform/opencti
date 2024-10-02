import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import StixCoreObjectHistoryLines, { stixCoreObjectHistoryLinesQuery } from './StixCoreObjectHistoryLines';
import { QueryRenderer } from '../../../../relay/environment';
import SearchInput from '../../../../components/SearchInput';
import Loader from '../../../../components/Loader';

const styles = (theme) => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: theme.spacing(2),
    marginTop: theme.spacing(1),
  },
});

class StixCoreObjectHistory extends Component {
  constructor(props) {
    super(props);
    this.state = { entitySearchTerm: '', relationsSearchTerm: '' };
  }

  handleSearchEntity(value) {
    this.setState({ entitySearchTerm: value });
  }

  handleSearchRelations(value) {
    this.setState({ relationsSearchTerm: value });
  }

  render() {
    const { classes, t, stixCoreObjectId, withoutRelations } = this.props;
    const { entitySearchTerm, relationsSearchTerm } = this.state;
    return (
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
        data-testid='sco-history-content'
      >
        <Grid
          item
          xs={withoutRelations ? 12 : 6}
          style={{ paddingTop: 0 }}
        >
          <Typography
            variant="h4"
            gutterBottom={true}
            style={{ float: 'left', marginTop: 12 }}
          >
            {t('Entity')}
          </Typography>
          <div style={{ float: 'right' }}>
            <SearchInput
              variant="thin"
              onSubmit={this.handleSearchEntity.bind(this)}
              keyword={entitySearchTerm}
            />
          </div>
          <div className="clearfix" />
          <QueryRenderer
            query={stixCoreObjectHistoryLinesQuery}
            variables={{
              filters: {
                mode: 'and',
                filterGroups: [],
                filters: [
                  { key: 'context_data.id', values: [stixCoreObjectId] },
                  {
                    key: 'event_type',
                    values: ['mutation', 'create', 'update', 'delete', 'merge'],
                  },
                ],
              },
              first: 20,
              orderBy: 'timestamp',
              orderMode: 'desc',
              search: entitySearchTerm,
            }}
            render={({ props }) => {
              if (props) {
                return (
                  <StixCoreObjectHistoryLines
                    stixCoreObjectId={stixCoreObjectId}
                    data={props}
                    isRelationLog={false}
                  />
                );
              }
              return <Loader variant="inElement" />;
            }}
          />
        </Grid>
        {!withoutRelations && (
          <Grid item xs={6} style={{ paddingTop: 0 }}>
            <Typography
              variant="h4"
              gutterBottom={true}
              style={{ float: 'left', marginTop: 10 }}
            >
              {t('Relations of the entity')}
            </Typography>
            <div style={{ float: 'right' }}>
              <SearchInput
                variant="thin"
                onSubmit={this.handleSearchRelations.bind(this)}
                keyword={entitySearchTerm}
              />
            </div>
            <div className="clearfix" />
            <QueryRenderer
              query={stixCoreObjectHistoryLinesQuery}
              variables={{
                filters: {
                  mode: 'and',
                  filters: [
                    {
                      key: 'event_type',
                      values: ['create', 'delete', 'mutation'], // retro-compatibility
                    },
                  ],
                  filterGroups: [{
                    mode: 'or',
                    filters: [
                      {
                        key: 'event_scope',
                        values: ['create', 'delete'],
                      },
                      {
                        key: 'event_scope',
                        values: [], // if event_scope is null, event_type is not
                        operator: 'nil',
                      },
                    ],
                    filterGroups: [],
                  },
                  {
                    mode: 'or',
                    filters: [
                      {
                        key: 'context_data.from_id',
                        values: [stixCoreObjectId],
                      },
                      {
                        key: 'context_data.to_id',
                        values: [stixCoreObjectId],
                      },
                    ],
                    filterGroups: [],
                  }],
                },
                first: 20,
                orderBy: 'timestamp',
                orderMode: 'desc',
                search: relationsSearchTerm,
              }}
              render={({ props }) => {
                if (props) {
                  return (
                    <StixCoreObjectHistoryLines
                      stixCoreObjectId={stixCoreObjectId}
                      data={props}
                      isRelationLog={true}
                    />
                  );
                }
                return <Loader variant="inElement" />;
              }}
            />
          </Grid>
        )}
      </Grid>
    );
  }
}

StixCoreObjectHistory.propTypes = {
  t: PropTypes.func,
  stixCoreObjectId: PropTypes.string,
  withoutRelations: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(StixCoreObjectHistory);
