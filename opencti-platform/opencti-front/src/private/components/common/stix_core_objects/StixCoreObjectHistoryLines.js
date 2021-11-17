import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import { createRefetchContainer } from 'react-relay';
import Paper from '@material-ui/core/Paper';
import inject18n from '../../../../components/i18n';
import StixCoreObjectHistoryLine from './StixCoreObjectHistoryLine';

const styles = () => ({
  paperHistory: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: '15px 15px 0 15px',
    borderRadius: 6,
  },
});

class StixCoreObjectHistoryLinesComponent extends Component {
  render() {
    const {
      t, classes, data, isRelationLog,
    } = this.props;
    const logs = pathOr([], ['logs', 'edges'], data);
    return (
      <Paper classes={{ root: classes.paperHistory }} elevation={2}>
        {logs.length > 0 ? (
          logs.map((logEdge) => {
            const log = logEdge.node;
            return (
              <StixCoreObjectHistoryLine
                key={log.id}
                node={log}
                isRelation={isRelationLog}
              />
            );
          })
        ) : (
          <div style={{ display: 'table', height: '100%', width: '100%' }}>
            <span
              style={{
                display: 'table-cell',
                verticalAlign: 'middle',
                textAlign: 'center',
              }}
            >
              {isRelationLog
                ? t('No relations history about this entity.')
                : t('No history about this entity.')}
            </span>
          </div>
        )}
      </Paper>
    );
  }
}

StixCoreObjectHistoryLinesComponent.propTypes = {
  stixCoreObjectId: PropTypes.string,
  isRelationLog: PropTypes.bool,
  data: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixCoreObjectHistoryLinesQuery = graphql`
  query StixCoreObjectHistoryLinesQuery(
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: [LogsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    ...StixCoreObjectHistoryLines_data
  }
`;

const StixCoreObjectHistoryLines = createRefetchContainer(
  StixCoreObjectHistoryLinesComponent,
  {
    data: graphql`
      fragment StixCoreObjectHistoryLines_data on Query {
        logs(
          first: $first
          orderBy: $orderBy
          orderMode: $orderMode
          filters: $filters
          filterMode: $filterMode
          search: $search
        ) {
          edges {
            node {
              id
              ...StixCoreObjectHistoryLine_node
            }
          }
        }
      }
    `,
  },
  stixCoreObjectHistoryLinesQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCoreObjectHistoryLines);
