/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createPaginationContainer, createFragmentContainer } from 'react-relay';
import {
  map, filter, head, compose,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Checkbox from '@material-ui/core/Checkbox';
import graphql from 'babel-plugin-relay/macro';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import { ConnectionHandler } from 'relay-runtime';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';
import Typography from '@material-ui/core/Typography';

const styles = (theme) => ({
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
  list: {
    marginLeft: '24px',
    marginRight: '24px',
  },
});

export const cyioExternalReferenceLinesMutationRelationAdd = graphql`
  mutation CyioAddExternalReferencesLinesRelationAddMutation(
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
    $from_type: String
    $to_type: String!
  ) {
    addReference(input:  {field_name: $fieldName, from_id: $fromId, to_id: $toId, from_type: $from_type, to_type: $to_type})
  }
`;

export const cyioExternalReferenceMutationRelationDelete = graphql`
  mutation CyioAddExternalReferencesLinesRelationDeleteMutation(
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
    $from_type: String
    $to_type: String!
  ) {
    removeReference(input:  {field_name: $fieldName, from_id: $fromId, to_id: $toId, from_type: $from_type, to_type: $to_type})
    # # externalReferenceEdit(id: $id) {
    #   relationDelete(fromId: $fromId, relationship_type: $relationship_type) {
    #     id
    #   }
    # }
  }
`;

const sharedUpdater = (store, cyioCoreObjectId, newEdge) => {
  const entity = store.get(cyioCoreObjectId);
  const conn = ConnectionHandler.getConnection(
    entity,
    // 'Pagination_externalReferences',
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class CyioAddExternalReferencesLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      addExternalReference: [],
    };
  }

  toggleExternalReference(externalReference, event) {
    const {
      cyioCoreObjectOrCyioCoreRelationshipId,
      cyioCoreObjectOrCyioCoreRelationshipReferences,
    } = this.props;
    const cyioCoreObjectOrCyioCoreRelationshipReferencesIds = map(
      (n) => n.id,
      cyioCoreObjectOrCyioCoreRelationshipReferences,
    );
    const alreadyAdded = cyioCoreObjectOrCyioCoreRelationshipReferencesIds.includes(
      externalReference.id,
    );
    if (event.target.checked && !alreadyAdded) {
      this.state.addExternalReference.push(externalReference);
    }
    else {
      this.state.addExternalReference = this.state.addExternalReference.filter((value) => value.id !== externalReference.id)
    }
    this.props.handleDataCollect(this.state.addExternalReference);
  }

  render() {
    const {
      t,
      classes,
      data,
      cyioCoreObjectOrCyioCoreRelationshipReferences,
    } = this.props;
    const cyioCoreObjectOrCyioCoreRelationshipReferencesIds = map(
      (n) => n.id,
      cyioCoreObjectOrCyioCoreRelationshipReferences || []);
    const filteredValue = data.cyioExternalReferences
      ? filter((value) => (value.node.source_name.toLowerCase()).includes(this.props.search), data.cyioExternalReferences.edges)
      : [];
    return (
      <div>
        <List className={classes.list}>
          {filteredValue.length > 0 ? filteredValue.map((externalReferenceNode) => {
            const externalReference = externalReferenceNode.node;
            const alreadyAdded = cyioCoreObjectOrCyioCoreRelationshipReferencesIds.includes(
              externalReference.id,
            );
            const externalReferenceId = externalReference.external_id
              ? `(${externalReference.external_id})`
              : '';
            return (
              <ListItem
                key={externalReference.id}
                classes={{ root: classes.menuItem }}
                disabled={alreadyAdded ? true : false}
                divider={true}
                button={true}
              >
                <ListItemIcon>
                  {alreadyAdded ? (
                    <Checkbox checked classes={{ root: classes.icon }} />
                  ) : (
                    <Checkbox
                      onChange={this.toggleExternalReference.bind(
                        this,
                        externalReference,
                      )}
                      classes={{ root: classes.icon }}
                    />
                  )}
                </ListItemIcon>
                <ListItemText
                  primary={`${externalReference.source_name} ${externalReferenceId}`}
                  secondary={<Markdown
                    remarkPlugins={[remarkGfm, remarkParse]}
                    parserOptions={{ commonmark: true }}
                    className="markdown">
                    {truncate(
                      externalReference.description !== null
                        && externalReference.description.length > 0
                        ? externalReference.description
                        : externalReference.url,
                      120,
                    )}
                  </Markdown>}
                />
              </ListItem>
            );
          })
            : (
              <Typography style={{ padding: '20px 0', textAlign: 'center' }}>
                {t('No Entries')}
              </Typography>
            )}
        </List>
      </div>
    );
  }
}

CyioAddExternalReferencesLinesContainer.propTypes = {
  cyioCoreObjectOrCyioCoreRelationshipId: PropTypes.string,
  cyioCoreObjectOrCyioCoreRelationshipReferences: PropTypes.array,
  data: PropTypes.object,
  typename: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
  handleDataCollect: PropTypes.func,
  t: PropTypes.func,
  fld: PropTypes.func,
  paginationOptions: PropTypes.object,
  open: PropTypes.bool,
  search: PropTypes.string,
};

export const cyioAddExternalReferencesLinesQuery = graphql`
  query CyioAddExternalReferencesLinesQuery(
    $count: Int!
  ) {
    ...CyioAddExternalReferencesLines_data
    @arguments(count: $count)
  }
`;

const CyioAddExternalReferencesLines = createFragmentContainer(
  CyioAddExternalReferencesLinesContainer,
  {
    data: graphql`
      fragment CyioAddExternalReferencesLines_data on Query
      @argumentDefinitions(
        count: { type: "Int", defaultValue: 4 }
      ) {
        cyioExternalReferences(limit: $count) {
          edges {
            cursor
            node {
              __typename
              id
              created
              modified
              source_name
              entity_type
              description
              url
              hashes {
                algorithm
                value
              }
              external_id
              reference_purpose
              media_type
            }
          }
          pageInfo {
            globalCount
            startCursor
            endCursor
            hasNextPage
            hasPreviousPage
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(CyioAddExternalReferencesLines);
