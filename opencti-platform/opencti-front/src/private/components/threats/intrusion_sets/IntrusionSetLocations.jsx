import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import IconButton from '@common/button/IconButton';
import { LinkOff } from '@mui/icons-material';
import { graphql, createFragmentContainer } from 'react-relay';
import * as R from 'ramda';
import { ListItemButton } from '@mui/material';
import AddLocations from './AddLocations';
import { addLocationsMutationRelationDelete } from './AddLocationsLines';
import { APP_BASE_PATH, commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import ItemIcon from '../../../../components/ItemIcon';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

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
        const newEdges = edges.filter(
          (n) => n.getLinkedRecord('node').getValue('id') !== locationEdge.node.id,
        );
        locations.setLinkedRecords(newEdges, 'edges');
      },
    });
  }

  render() {
    const { t, intrusionSet } = this.props;
    return (
      <>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Originates from')}
        </Typography>
        <Security
          needs={[KNOWLEDGE_KNUPDATE]}
        >
          <AddLocations
            intrusionSet={intrusionSet}
            intrusionSetLocations={intrusionSet.locations.edges}
          />
        </Security>
        <div className="clearfix" />
        <FieldOrEmpty source={intrusionSet.locations.edges}>
          <List style={{ marginTop: -10 }}>
            {intrusionSet.locations.edges.map((locationEdge) => {
              const location = locationEdge.node;
              const link = resolveLink(location.entity_type);
              const flag = location.entity_type === 'Country'
                && R.head(
                  (location.x_opencti_aliases ?? []).filter(
                    (n) => n?.length === 2,
                  ),
                );
              return (
                <ListItem
                  key={location.id}
                  dense={true}
                  divider={true}
                  disablePadding
                  secondaryAction={(
                    <Security needs={[KNOWLEDGE_KNUPDATE]}>
                      <IconButton
                        aria-label="Remove"
                        onClick={this.removeLocation.bind(this, locationEdge)}
                      >
                        <LinkOff />
                      </IconButton>
                    </Security>
                  )}
                >
                  <ListItemButton
                    component={Link}
                    to={`${link}/${location.id}`}
                  >
                    <ListItemIcon>
                      <ListItemIcon>
                        {flag ? (
                          <img
                            style={{ width: 20 }}
                            src={`${APP_BASE_PATH}/static/flags/4x3/${flag.toLowerCase()}.svg`}
                            alt={location.name}
                          />
                        ) : (
                          <ItemIcon type={location.entity_type} />
                        )}
                      </ListItemIcon>
                    </ListItemIcon>
                    <ListItemText primary={location.name} />
                  </ListItemButton>
                </ListItem>
              );
            })}
          </List>
        </FieldOrEmpty>
      </>
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
        name
        parent_types
        entity_type
        locations {
          edges {
            node {
              id
              parent_types
              entity_type
              name
              x_opencti_aliases
              description
            }
          }
        }
      }
    `,
  },
);

export default compose(inject18n, withStyles(styles))(IntrusionSetLocations);
