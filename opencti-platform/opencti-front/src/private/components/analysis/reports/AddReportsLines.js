import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createPaginationContainer } from 'react-relay';
import { map, filter, head, compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Avatar from '@mui/material/Avatar';
import { CheckCircle } from '@mui/icons-material';
import { ConnectionHandler } from 'relay-runtime';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';

const styles = (theme) => ({
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

const reportLinesMutationRelationAdd = graphql`
  mutation AddReportsLinesRelationAddMutation(
    $id: ID!
    $input: StixMetaRelationshipAddInput!
  ) {
    reportEdit(id: $id) {
      relationAdd(input: $input) {
        id
        to {
          ... on Report {
            id
            name
            description
            published
          }
        }
      }
    }
  }
`;

export const reportMutationRelationDelete = graphql`
  mutation AddReportsLinesRelationDeleteMutation(
    $id: ID!
    $toId: StixRef!
    $relationship_type: String!
  ) {
    reportEdit(id: $id) {
      relationDelete(toId: $toId, relationship_type: $relationship_type) {
        id
      }
    }
  }
`;

const sharedUpdater = (store, entityId, newEdge) => {
  const entity = store.get(entityId);
  const conn = ConnectionHandler.getConnection(entity, 'Pagination_reports');
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class AddReportsLinesContainer extends Component {
  toggleReport(report) {
    const { entityId, entityReports } = this.props;
    const entityReportsIds = map((n) => n.node.id, entityReports);
    const alreadyAdded = entityReportsIds.includes(report.id);

    if (alreadyAdded) {
      const existingReport = head(
        filter((n) => n.node.id === report.id, entityReports),
      );
      commitMutation({
        mutation: reportMutationRelationDelete,
        variables: {
          id: entityId,
          toId: existingReport.id,
          relationship_type: 'external-reference',
        },
        updater: (store) => {
          const entity = store.get(entityId);
          const conn = ConnectionHandler.getConnection(
            entity,
            'Pagination_reports',
          );
          ConnectionHandler.deleteNode(conn, report.id);
        },
      });
    } else {
      const input = {
        fromId: entityId,
        relationship_type: 'external-reference',
      };
      commitMutation({
        mutation: reportLinesMutationRelationAdd,
        variables: {
          id: report.id,
          input,
        },
        updater: (store) => {
          const payload = store
            .getRootField('reportEdit')
            .getLinkedRecord('relationAdd', { input });
          const relationId = payload.getValue('id');
          const node = payload.getLinkedRecord('to');
          const relation = store.get(relationId);
          payload.setLinkedRecord(node, 'node');
          payload.setLinkedRecord(relation, 'relation');
          sharedUpdater(store, entityId, payload);
        },
      });
    }
  }

  render() {
    const { classes, data, entityReports } = this.props;
    const entityReportsIds = map((n) => n.node.id, entityReports);
    return (
      <List>
        {data.reports.edges.map((reportNode) => {
          const report = reportNode.node;
          const alreadyAdded = entityReportsIds.includes(report.id);
          const reportId = report.external_id ? `(${report.external_id})` : '';
          return (
            <ListItem
              key={report.id}
              classes={{ root: classes.menuItem }}
              divider={true}
              button={true}
              onClick={this.toggleReport.bind(this, report)}
            >
              <ListItemIcon>
                {alreadyAdded ? (
                  <CheckCircle classes={{ root: classes.icon }} />
                ) : (
                  <Avatar classes={{ root: classes.avatar }}>
                    {report.source_name.substring(0, 1)}
                  </Avatar>
                )}
              </ListItemIcon>
              <ListItemText
                primary={`${report.source_name} ${reportId}`}
                secondary={truncate(
                  report.description !== null && report.description.length > 0
                    ? report.description
                    : report.url,
                  120,
                )}
              />
            </ListItem>
          );
        })}
      </List>
    );
  }
}

AddReportsLinesContainer.propTypes = {
  entityId: PropTypes.string,
  entityReports: PropTypes.array,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export const addReportsLinesQuery = graphql`
  query AddReportsLinesQuery($search: String, $count: Int!, $cursor: ID) {
    ...AddReportsLines_data
      @arguments(search: $search, count: $count, cursor: $cursor)
  }
`;

const AddReportsLines = createPaginationContainer(
  AddReportsLinesContainer,
  {
    data: graphql`
      fragment AddReportsLines_data on Query
      @argumentDefinitions(
        search: { type: "String" }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
      ) {
        reports(search: $search, first: $count, after: $cursor)
          @connection(key: "Pagination_reports") {
          edges {
            node {
              id
              name
              description
              published
            }
          }
        }
      }
    `,
  },
  {
    direction: 'forward',
    getConnectionFromProps(props) {
      return props.data && props.data.reports;
    },
    getFragmentVariables(prevVars, totalCount) {
      return {
        ...prevVars,
        count: totalCount,
      };
    },
    getVariables(props, { count, cursor }) {
      return {
        count,
        cursor,
      };
    },
    query: addReportsLinesQuery,
  },
);

export default compose(inject18n, withStyles(styles))(AddReportsLines);
