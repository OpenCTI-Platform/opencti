import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { LinkOff } from '@mui/icons-material';
import { graphql, createFragmentContainer } from 'react-relay';
import AddLocations from './AddLocations';
import { addLocationsMutationRelationDelete } from './AddLocationsLines';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import ItemIcon from '../../../../components/ItemIcon';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

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

class IntrusionSetLocationsComponent extends Component {
  removeLocation(locationEdge) {
    commitMutation({
      mutation: addLocationsMutationRelationDelete,
      variables: {
        fromId: this.props.intrusionSet.id,
        toId: locationEdge.node.id,
        relationship_type: 'originates-from',
      },
      updater: (store) => {
        const node = store.get(this.props.intrusionSet.id);
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
    const { t, intrusionSet } = this.props;
    return (
      <div style={{ marginTop: -20 }}>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Originates from')}
        </Typography>
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
          placeholder={<div style={{ marginTop: 20, height: 29 }} />}
        >
          <AddLocations
            intrusionSetId={intrusionSet.id}
            intrusionSetLocations={intrusionSet.locations.edges}
          />
        </Security>
        <div className="clearfix" />
        <List style={{ marginTop: -10 }}>
          {intrusionSet.locations.edges.map((locationEdge) => {
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
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <ListItemSecondaryAction>
                    <IconButton
                      aria-label="Remove"
                      onClick={this.removeLocation.bind(this, locationEdge)}
                      size="large"
                    >
                      <LinkOff />
                    </IconButton>
                  </ListItemSecondaryAction>
                </Security>
              </ListItem>
            );
          })}
        </List>
      </div>
    );
  }
}

IntrusionSetLocationsComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  intrusionSet: PropTypes.object,
};

const IntrusionSetLocations = createFragmentContainer(
  IntrusionSetLocationsComponent,
  {
    intrusionSet: graphql`
      fragment IntrusionSetLocations_intrusionSet on IntrusionSet {
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

export default compose(inject18n, withStyles(styles))(IntrusionSetLocations);
