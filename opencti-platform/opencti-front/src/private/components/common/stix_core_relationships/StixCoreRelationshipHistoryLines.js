import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, pathOr } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import { graphql, createRefetchContainer } from 'react-relay';
import Paper from '@mui/material/Paper';
import { interval } from 'rxjs';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipHistoryLine from './StixCoreRelationshipHistoryLine';
import { FIVE_SECONDS } from '../../../../utils/Time';

const interval$ = interval(FIVE_SECONDS);

const styles = () => ({
  paperHistory: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 15,
    borderRadius: 6,
  },
});

class StixCoreRelationshipHistoryLinesComponent extends Component {
  componentDidMount() {
    this.subscription = interval$.subscribe(() => {
      this.props.relay.refetch();
    });
  }

  componentWillUnmount() {
    this.subscription.unsubscribe();
  }

  render() {
    const { t, classes, data, isRelationLog } = this.props;
    const logs = pathOr([], ['logs', 'edges'], data);
    return (
      <Paper classes={{ root: classes.paperHistory }} variant="outlined">
        {logs.length > 0 ? (
          logs.map((logEdge) => {
            const log = logEdge.node;
            return (
              <StixCoreRelationshipHistoryLine
                key={log.id}
                node={log}
                isRelation={isRelationLog}
              />
            );
          })
        ) : (
          <div
            style={{
              display: 'table',
              height: '100%',
              width: '100%',
            }}
          >
            <span
              style={{
                display: 'table-cell',
                verticalAlign: 'middle',
                textAlign: 'center',
              }}
            >
              {isRelationLog
                ? t('No relations history about this relationship.')
                : t('No history about this relationship.')}
            </span>
          </div>
        )}
      </Paper>
    );
  }
}

StixCoreRelationshipHistoryLinesComponent.propTypes = {
  stixCoreObjectId: PropTypes.string,
  isRelationLog: PropTypes.bool,
  data: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixCoreObjectHistoryLinesQuery = graphql`
  query StixCoreRelationshipHistoryLinesQuery(
    $first: Int
    $orderBy: LogsOrdering
    $orderMode: OrderingMode
    $filters: [LogsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    ...StixCoreRelationshipHistoryLines_data
  }
`;

const StixCoreRelationshipHistoryLines = createRefetchContainer(
  StixCoreRelationshipHistoryLinesComponent,
  {
    data: graphql`
      fragment StixCoreRelationshipHistoryLines_data on Query {
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
              ...StixCoreRelationshipHistoryLine_node
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
)(StixCoreRelationshipHistoryLines);
