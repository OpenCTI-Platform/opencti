import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
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
import * as R from 'ramda';
import { AutoFix } from 'mdi-material-ui';
import { APP_BASE_PATH, commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import ItemIcon from '../../../../components/ItemIcon';
import { KnowledgeSecurity } from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import AddLocationsThreatActorGroup from './AddLocationsThreatActorGroup';
import { addLocationsThreatActorGroupMutationRelationDelete } from './AddLocationsThreatActorGroupLines';

class ThreatActorGroupLocationsComponent extends Component {
  removeLocation(locationEdge) {
    commitMutation({
      mutation: addLocationsThreatActorGroupMutationRelationDelete,
      variables: {
        fromId: this.props.threatActorGroup.id,
        toId: locationEdge.node.id,
        relationship_type: 'located-at',
      },
      updater: (store) => {
        const node = store.get(this.props.threatActorGroup.id);
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
    const { t, threatActorGroup } = this.props;
    return (
      <>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Located at')}
        </Typography>
        <KnowledgeSecurity
          needs={[KNOWLEDGE_KNUPDATE]}
          entity='Threat-Actor-Group'
          placeholder={<div style={{ height: 29 }} />}
        >
          <AddLocationsThreatActorGroup
            threatActorGroup={threatActorGroup}
            threatActorGroupLocations={threatActorGroup.locations.edges}
          />
        </KnowledgeSecurity>
        <div className="clearfix" />
        <List style={{ marginTop: -10 }}>
          {threatActorGroup.locations.edges.length === 0 && (
            <ListItem dense={true} divider={true} button={false}>
              <ListItemText primary="-" />
            </ListItem>
          )}
          {threatActorGroup.locations.edges.map((locationEdge) => {
            const { types } = locationEdge;
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
                button={true}
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
                {types.includes('manual') ? (
                  <ListItemSecondaryAction>
                    <KnowledgeSecurity needs={[KNOWLEDGE_KNUPDATE]} entity='Threat-Actor-Group'>
                      <IconButton
                        aria-label="Remove"
                        onClick={() => this.removeLocation(locationEdge)}
                        size="large"
                      >
                        <LinkOff />
                      </IconButton>
                    </KnowledgeSecurity>
                  </ListItemSecondaryAction>
                ) : <AutoFix fontSize="small" style={{ marginRight: 13 }}/>}
              </ListItem>
            );
          })}
        </List>
      </>
    );
  }
}

ThreatActorGroupLocationsComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  threatActorGroup: PropTypes.object,
};

const ThreatActorGroupLocations = createFragmentContainer(
  ThreatActorGroupLocationsComponent,
  {
    threatActorGroup: graphql`
      fragment ThreatActorGroupLocations_locations on ThreatActorGroup {
        id
        name
        parent_types
        entity_type
        locations {
          edges {
            types
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

export default compose(inject18n)(ThreatActorGroupLocations);
