import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose, head, map } from 'ramda';
import { commitMutation, QueryRenderer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import IconButton from '@material-ui/core/IconButton';
import Avatar from '@material-ui/core/Avatar';
import { LinkOff } from '@material-ui/icons';
import { ConnectionHandler } from 'relay-runtime';
import inject18n from '../../../components/i18n';
import truncate from '../../../utils/String';
import environment from '../../../relay/environment';
import AddExternalReferences from './AddExternalReferences';

const styles = theme => ({
  paper: {
    minHeight: '100%',
    margin: '-4px 0 0 0',
    padding: 0,
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
  avatar: {
    width: 24,
    height: 24,
    backgroundColor: theme.palette.primary.main,
  },
  avatarDisabled: {
    width: 24,
    height: 24,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.text.disabled,
  },
});

export const externalReferenceMutationRelationDelete = graphql`
    mutation EntityExternalReferencesRelationDeleteMutation($id: ID!, $relationId: ID!) {
        externalReferenceEdit(id: $id) {
            relationDelete(relationId: $relationId)
        }
    }
`;

const entityExternalReferencesQuery = graphql`
    query EntityExternalReferencesQuery($objectId: String!, $first: Int) {
        externalReferencesOf(objectId: $objectId, first: $first) {
            edges {
                node {
                    id
                    source_name
                    description
                    url
                    hash
                    external_id
                }
                relation {
                    id
                }
            }
        }
    }
`;

class EntityExternalReferences extends Component {
  removeExternalReference(externalReferenceEdge) {
    commitMutation(environment, {
      mutation: externalReferenceMutationRelationDelete,
      variables: {
        id: externalReferenceEdge.node.id,
        relationId: externalReferenceEdge.relation.id,
      },
    });
  }

  render() {
    const { t, classes, entityId } = this.props;
    const paginationOptions = { objectId: entityId, first: 20 };
    return (
      <QueryRenderer
        environment={environment}
        query={entityExternalReferencesQuery}
        variables={paginationOptions}
        render={({ props }) => {
          if (props && props.externalReferencesOf) {
            return (
              <div style={{ height: '100%' }}>
                <Typography variant='h4' gutterBottom={true} style={{ float: 'left' }}>
                  {t('External references')}
                </Typography>
                <AddExternalReferences entityId={entityId} entityExternalReferences={props.externalReferencesOf.edges} paginationOptions={paginationOptions}/>
                <div className='clearfix'/>
                <Paper classes={{ root: classes.paper }} elevation={2}>
                  <List>
                    {props.externalReferencesOf.edges.map((externalReferenceEdge) => {
                      const externalReference = externalReferenceEdge.node;
                      if (externalReference.url) {
                        return (
                          <ListItem
                            key={externalReference.id}
                            dense={true}
                            divider={true}
                            button={true}
                            component='a'
                            href={externalReference.url}
                          >
                            <ListItemIcon >
                              <Avatar classes={{ root: classes.avatar }}>{externalReference.source_name.substring(0, 1)}</Avatar>
                            </ListItemIcon>
                            <ListItemText
                              primary={`${externalReference.source_name} ${externalReference.external_id}`}
                              secondary={truncate(externalReference.description !== null && externalReference.description.length > 0 ? externalReference.description : externalReference.url, 120)}
                            />
                            <ListItemSecondaryAction>
                              <IconButton aria-label='Remove' onClick={this.removeExternalReference.bind(this, externalReferenceEdge)}>
                                <LinkOff/>
                              </IconButton>
                            </ListItemSecondaryAction>
                          </ListItem>
                        );
                      }
                      return (
                        <ListItem
                          key={externalReference.id}
                          dense={true}
                          divider={true}
                          button={false}
                        >
                          <ListItemIcon>
                            <Avatar classes={{ root: classes.avatar }}>{externalReference.source_name.substring(0, 1)}</Avatar>
                          </ListItemIcon>
                          <ListItemText
                            primary={`${externalReference.source_name} ${externalReference.external_id}`}
                            secondary={truncate(externalReference.description, 120)}
                          />
                        </ListItem>
                      );
                    })}
                  </List>
                </Paper>
              </div>
            );
          }
          return (
            <div style={{ height: '100%' }}>
              <Typography variant='h4' gutterBottom={true} style={{ float: 'left' }}>
                {t('External references')}
              </Typography>
              <AddExternalReferences entityId='' entityExternalReferences={[]}/>
              <div className='clearfix'/>
              <Paper classes={{ root: classes.paper }} elevation={2}>
                <List>
                  {Array.from(Array(5), (e, i) => (
                    <ListItem
                      key={i}
                      dense={true}
                      divider={true}
                      button={false}
                    >
                      <ListItemIcon>
                        <Avatar classes={{ root: classes.avatarDisabled }}>{i}</Avatar>
                      </ListItemIcon>
                      <ListItemText
                        primary={<span className={classes.placeholder} style={{ width: '80%' }}/>}
                        secondary={<span className={classes.placeholder} style={{ width: '90%' }}/>}
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </div>
          );
        }}
      />
    );
  }
}

EntityExternalReferences.propTypes = {
  entityId: PropTypes.string,
  limit: PropTypes.number,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityExternalReferences);
