/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import {
  map, filter, compose,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import Checkbox from '@material-ui/core/Checkbox';
import ListItemText from '@material-ui/core/ListItemText';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import rehypeRaw from 'rehype-raw';
import Typography from '@material-ui/core/Typography';

const styles = (theme) => ({
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

export const cyioNoteLinesMutationRelationAdd = graphql`
  mutation CyioAddNotesLinesRelationAddMutation(
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
    $to_type: String
    $from_type: String
  ) {
    addReference(input: {field_name: $fieldName, from_id: $fromId, to_id: $toId, to_type: $to_type, from_type: $from_type})
  }
`;

export const cyioNoteMutationRelationDelete = graphql`
  mutation CyioAddNotesLinesRelationDeleteMutation(
    $fieldName: String!
    $fromId: ID!
    $toId: ID!
    $to_type: String
    $from_type: String
  ) {
    removeReference(input: {field_name: $fieldName, from_id: $fromId, to_id: $toId, to_type: $to_type, from_type: $from_type})
  }
`;

const sharedUpdater = (store, entityId, newEdge) => {
  const entity = store.get(entityId);
  const conn = ConnectionHandler.getConnection(entity, 'Pagination_notes');
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class CyioAddNotesLinesContainer extends Component {
  constructor(props) {
    super(props);
    this.state = {
      addNotes: [],
    };
  }
  toggleNote(note, event) {
    const {
      cyioCoreObjectOrStixCoreRelationshipId,
      cyioCoreObjectOrStixCoreRelationshipNotes,
    } = this.props;
    const entityNotesIds = map(
      (n) => n.id,
      cyioCoreObjectOrStixCoreRelationshipNotes,
    );
    const alreadyAdded = entityNotesIds.includes(note.id);
    if (event.target.checked && !alreadyAdded) {
      this.state.addNotes.push(note);
    }
    else {
      this.state.addNotes = this.state.addNotes.filter((value) => value.id !== note.id)
    }
    this.props.handleDataCollect(this.state.addNotes);
  }

  render() {
    const {
      classes,
      data,
      cyioCoreObjectOrStixCoreRelationshipNotes,
      t,
    } = this.props;
    const entityNotesIds = map(
      (n) => n.id,
      cyioCoreObjectOrStixCoreRelationshipNotes,
    );
    const filteredValue = data.cyioNotes
      ? filter((value) => (value.node.abstract.toLowerCase()).includes(this.props.search.toLowerCase()), data.cyioNotes.edges)
      : [];
    return (
      <List>
        {filteredValue.length > 0 ? filteredValue.map((noteNode) => {
          const note = noteNode.node;
          const alreadyAdded = entityNotesIds.includes(note.id);
          const noteId = note.external_id ? `(${note.external_id})` : '';
          return (
            <ListItem
              key={note.id}
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
                    onChange={this.toggleNote.bind(
                      this,
                      note,
                    )}
                    classes={{ root: classes.icon }}
                  />
                )}
              </ListItemIcon>
              <ListItemText
                primary={`${note.abstract} ${noteId}`}
                secondary={<Markdown
                  remarkPlugins={[remarkGfm, remarkParse]}
                  rehypePlugins={[rehypeRaw]}
                  parserOptions={{ commonmark: true }}
                  className="markdown">
                  {truncate(note.content, 120)}
                </Markdown>}
              />
              {/* <div style={{ marginRight: 50 }}>
                {pathOr([], ['objectMarking', 'edges'], note).length > 0
                  && map(
                    (markingDefinition) => (
                      <ItemMarking
                        key={markingDefinition.node.id}
                        label={markingDefinition.node.definition}
                        variant="inList"
                      />
                    ),
                    note.objectMarking.edges,
                  )}
              </div> */}
            </ListItem>
          );
        }) : (
          <Typography style={{ padding: '20px 0', textAlign: 'center' }}>
            {t('No Entries')}
          </Typography>
        )}
      </List>
    );
  }
}

CyioAddNotesLinesContainer.propTypes = {
  cyioCoreObjectOrStixCoreRelationshipId: PropTypes.string,
  cyioCoreObjectOrStixCoreRelationshipNotes: PropTypes.array,
  typename: PropTypes.string,
  data: PropTypes.object,
  limit: PropTypes.number,
  classes: PropTypes.object,
  handleDataCollect: PropTypes.func,
  t: PropTypes.func,
  search: PropTypes.string,
  fld: PropTypes.func,
};

export const cyioAddNotesLinesQuery = graphql`
  query CyioAddNotesLinesQuery(
    $search: String
  ) {
    ...CyioAddNotesLines_data
    @arguments(
      search: $search
    )
  }
`;

const CyioAddNotesLines = createFragmentContainer(
  CyioAddNotesLinesContainer,
  {
    data: graphql`
      fragment CyioAddNotesLines_data on Query 
      @argumentDefinitions(
        search: { type: "String" }
      ){
        cyioNotes(search: $search){
          edges {
            node {
              __typename
              id
              created
              modified
              entity_type
              labels {
                __typename
                id
                name
                color
                entity_type
                description
              }
              abstract
              content
              authors
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(CyioAddNotesLines);
