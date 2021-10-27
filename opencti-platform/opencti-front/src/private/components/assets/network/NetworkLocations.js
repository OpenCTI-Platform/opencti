import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { Link } from 'react-router-dom';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import IconButton from '@material-ui/core/IconButton';
import { LinkOff } from '@material-ui/icons';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import AddLocations from './AddLocations';
import { addLocationsMutationRelationDelete } from '../../threats/intrusion_sets/AddLocationsLines';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import ItemIcon from '../../../../components/ItemIcon';

const styles = (theme) => ({
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
    backgroundColor: theme.palette.grey[700],
  },
});

class NetworkLocationsComponent extends Component {
  removeLocation(locationEdge) {
    commitMutation({
      mutation: addLocationsMutationRelationDelete,
      variables: {
        fromId: this.props.network.id,
        toId: locationEdge.node.id,
        relationship_type: 'originates-from',
      },
      updater: (store) => {
        const node = store.get(this.props.network.id);
        const locations = node.getLinkedRecord('locations');
        const edges = locations.getLinkedRecords('edges');
        const newEdges = filter(
          (n) => n.getLinkedRecord('node').getValue('id') !== locationEdge.node.id,
          edges,
        );
        locations.setLinkedRecords(newEdges, 'edges');
      },
    });
  }

  render() {
    const { t, network } = this.props;
    return (
      <div style={{ marginTop: -20 }}>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Originates from')}
        </Typography>
        <AddLocations
          networkId={network.id}
          networkLocations={network.locations.edges}
        />
        <div className="clearfix" />
        <List style={{ marginTop: -10 }}>
          {network.locations.edges.map((locationEdge) => {
            const location = locationEdge.node;
            const link = resolveLink(location.entity_type);
            return (
              <ListItem
                key={location.id}
                dense={true}
                divider={true}
                button={true}
                component={Link}
                to={`${link}/${location.id}`}
              >
                <ListItemIcon>
                  <ListItemIcon>
                    <ItemIcon type={location.entity_type} />
                  </ListItemIcon>
                </ListItemIcon>
                <ListItemText primary={location.name} />
                <ListItemSecondaryAction>
                  <IconButton
                    aria-label="Remove"
                    onClick={this.removeLocation.bind(this, locationEdge)}
                  >
                    <LinkOff />
                  </IconButton>
                </ListItemSecondaryAction>
              </ListItem>
            );
          })}
        </List>
      </div>
    );
  }
}

NetworkLocationsComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  network: PropTypes.object,
};

const NetworkLocations = createFragmentContainer(
  NetworkLocationsComponent,
  {
    network: graphql`
      fragment NetworkLocations_network on IntrusionSet {
        id
        locations {
          edges {
            node {
              id
              entity_type
              name
              description
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(NetworkLocations);
