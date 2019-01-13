import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { commitMutation, QueryRenderer } from 'react-relay';
import {
  compose, map, filter, head,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import IconButton from '@material-ui/core/IconButton';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Typography from '@material-ui/core/Typography';
import Avatar from '@material-ui/core/Avatar';
import { Add, Close, CheckCircle } from '@material-ui/icons';
import graphql from 'babel-plugin-relay/macro';
import { ConnectionHandler } from 'relay-runtime';
import truncate from '../../../utils/String';
import inject18n from '../../../components/i18n';
import SearchInput from '../../../components/SearchInput';
import environment from '../../../relay/environment';
import { externalReferencesLinesSearchQuery } from './ExternalReferencesLines';
import { externalReferenceMutationRelationDelete } from './EntityExternalReferencesLines';

const styles = theme => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    backgroundColor: theme.palette.navAlt.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    float: 'left',
    marginTop: -15,
  },
  title: {
    float: 'left',
  },
  search: {
    float: 'right',
  },
  header: {
    backgroundColor: theme.palette.navAlt.backgroundHeader,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
  },
  container: {
    padding: 0,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.text.disabled,
  },
  avatar: {
    width: 24,
    height: 24,
  },
  icon: {
    color: theme.palette.primary.main,
  },
});

const externalReferenceMutationRelationAdd = graphql`
    mutation AddExternalReferencesRelationAddMutation($id: ID!, $input: RelationAddInput!) {
        externalReferenceEdit(id: $id) {
            relationAdd(input: $input) {
                from {
                    ... on ExternalReference {
                        id
                        source_name
                        description
                        url
                        hash
                        external_id
                    }
                }
                relation {
                    id
                }
            }
        }
    }
`;

const sharedUpdater = (store, userId, paginationOptions, newEdge) => {
  const userProxy = store.get(userId);
  const conn = ConnectionHandler.getConnection(
    userProxy,
    'Pagination_externalReferencesOf',
    paginationOptions,
  );
  ConnectionHandler.insertEdgeBefore(conn, newEdge);
};

class AddExternalReferences extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false, externalReferences: [], search: '' };
  }

  handleOpen() {
    this.setState({ open: true });
  }

  handleClose() {
    this.setState({ open: false });
  }

  handleSearch(event) {
    this.setState({ search: event.target.value });
  }

  toggleExternalReference(externalReference) {
    const { entityId, entityExternalReferences, paginationOptions } = this.props;
    const entityExternalReferencesIds = map(n => n.node.id, entityExternalReferences);
    const alreadyAdded = entityExternalReferencesIds.includes(externalReference.id);

    if (alreadyAdded) {
      const existingExternalReference = head(filter(n => n.node.id === externalReference.id, entityExternalReferences));
      commitMutation(environment, {
        mutation: externalReferenceMutationRelationDelete,
        variables: {
          id: externalReference.id,
          relationId: existingExternalReference.relation.id,
        },
        updater: (store) => {
          const container = store.getRoot();
          const userProxy = store.get(container.getDataID());
          const conn = ConnectionHandler.getConnection(
            userProxy,
            'Pagination_externalReferencesOf',
            this.props.paginationOptions,
          );
          ConnectionHandler.deleteNode(conn, externalReference.id);
        },
      });
    } else {
      const input = {
        fromRole: 'external_reference', toId: entityId, toRole: 'so', through: 'external_references',
      };
      commitMutation(environment, {
        mutation: externalReferenceMutationRelationAdd,
        variables: {
          id: externalReference.id,
          input,
        },
        updater: (store) => {
          const payload = store.getRootField('externalReferenceEdit').getLinkedRecord('relationAdd', { input }).getLinkedRecord('from');
          const newEdge = payload.setLinkedRecord(payload, 'node'); // Creation of the pagination container.
          const container = store.getRoot();
          sharedUpdater(store, container.getDataID(), paginationOptions, newEdge);
        },
      });
    }
  }

  render() {
    const { t, classes, entityExternalReferences } = this.props;
    const entityExternalReferencesIds = map(n => n.node.id, entityExternalReferences);
    return (
      <div>
        <IconButton color='secondary' aria-label='Add' onClick={this.handleOpen.bind(this)} classes={{ root: classes.createButton }}>
          <Add fontSize='small'/>
        </IconButton>
        <Drawer open={this.state.open} anchor='right' classes={{ paper: classes.drawerPaper }} onClose={this.handleClose.bind(this)}>
          <div className={classes.header}>
            <IconButton aria-label='Close' className={classes.closeButton} onClick={this.handleClose.bind(this)}>
              <Close fontSize='small'/>
            </IconButton>
            <Typography variant='h6' classes={{ root: classes.title }}>
              {t('Add external references')}
            </Typography>
            <div className={classes.search}>
              <SearchInput variant='controlled' placeholder={`${t('Search')}...`} handleSearch={this.handleSearch.bind(this)}/>
            </div>
          </div>
          <div className={classes.container}>
            <QueryRenderer
              environment={environment}
              query={externalReferencesLinesSearchQuery}
              variables={{ search: this.state.search, first: 20 }}
              render={({ props }) => {
                if (props && props.externalReferences) {
                  return (
                    <List>
                      {props.externalReferences.edges.map((externalReferenceNode) => {
                        const externalReference = externalReferenceNode.node;
                        const alreadyAdded = entityExternalReferencesIds.includes(externalReference.id);
                        return (
                          <ListItem
                            key={externalReference.id}
                            classes={{ root: classes.menuItem }}
                            divider={true}
                            button={true}
                            onClick={this.toggleExternalReference.bind(this, externalReference)}
                          >
                            <ListItemIcon>
                              {alreadyAdded ? <CheckCircle classes={{ root: classes.icon }} /> : <Avatar classes={{ root: classes.avatar }}>{externalReference.source_name.substring(0, 1)}</Avatar>}
                            </ListItemIcon>
                            <ListItemText
                              primary={`${externalReference.source_name} ${externalReference.external_id}`}
                              secondary={truncate(externalReference.description !== null && externalReference.description.length > 0 ? externalReference.description : externalReference.url, 120)}
                            />
                          </ListItem>
                        );
                      })}
                    </List>
                  );
                }
                return (
                  <List>
                    {Array.from(Array(20), (e, i) => (
                      <ListItem
                        key={i}
                        classes={{ root: classes.menuItem }}
                        divider={true}
                        button={false}
                      >
                        <ListItemIcon>
                          <Avatar classes={{ root: classes.avatar }}>{i}</Avatar>
                        </ListItemIcon>
                        <ListItemText
                          primary={<span className={classes.placeholder} style={{ width: '80%' }}/>}
                          secondary={<span className={classes.placeholder} style={{ width: '90%' }}/>}
                        />
                      </ListItem>
                    ))}
                  </List>
                );
              }}
            />
          </div>
        </Drawer>
      </div>
    );
  }
}

AddExternalReferences.propTypes = {
  entityId: PropTypes.string,
  entityExternalReferences: PropTypes.array,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(AddExternalReferences);
