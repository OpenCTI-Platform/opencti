import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { compose } from 'ramda';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import IconButton from '@mui/material/IconButton';
import { LinkOff } from '@mui/icons-material';
import { createFragmentContainer, graphql } from 'react-relay';
import { AutoFix } from 'mdi-material-ui';
import { ListItemButton } from '@mui/material';
import ListItem from '@mui/material/ListItem';
import CardTitle from '@common/card/CardTitle';
import { APP_BASE_PATH, commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import { resolveLink } from '../../../../utils/Entity';
import ItemIcon from '../../../../components/ItemIcon';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { addLocationsThreatActorMutationRelationDelete } from './AddLocationsThreatActorIndividualLines';
import AddLocationsThreatActorIndividual from './AddLocationsThreatActorIndividual';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';

class ThreatActorIndividualLocationsComponent extends Component {
  removeLocation(locationEdge) {
    commitMutation({
      mutation: addLocationsThreatActorMutationRelationDelete,
      variables: {
        fromId: this.props.threatActorIndividual.id,
        toId: locationEdge.node.id,
        relationship_type: 'located-at',
      },
      updater: (store) => {
        const node = store.get(this.props.threatActorIndividual.id);
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
    const { t, threatActorIndividual } = this.props;
    return (
      <>
        <CardTitle
          sx={{ marginTop: '20px' }}
          action={(
            <Security
              needs={[KNOWLEDGE_KNUPDATE]}
            >
              <AddLocationsThreatActorIndividual
                threatActorIndividual={threatActorIndividual}
              />
            </Security>
          )}
        >
          {t('Located at')}
        </CardTitle>
        <div className="clearfix" />
        <FieldOrEmpty source={threatActorIndividual.locations.edges}>
          <List style={{ marginTop: -10 }}>
            {threatActorIndividual.locations.edges.map((locationEdge) => {
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
                  disablePadding
                  secondaryAction={
                    types.includes('manual') && (
                      <div style={{ right: 0 }}>
                        <Security needs={[KNOWLEDGE_KNUPDATE]}>
                          <IconButton
                            aria-label="Remove"
                            onClick={() => this.removeLocation(locationEdge)}
                            size="large"
                          >
                            <LinkOff />
                          </IconButton>
                        </Security>
                      </div>
                    )
                  }
                >
                  <ListItemButton
                    component={Link}
                    to={`${link}/${location.id}`}
                  >
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
                    <ListItemText primary={location.name} />
                    {!types.includes('manual') && <AutoFix fontSize="small" style={{ marginRight: 13 }} />}
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

ThreatActorIndividualLocationsComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  threatActorIndividual: PropTypes.object,
};

const ThreatActorIndividualLocations = createFragmentContainer(
  ThreatActorIndividualLocationsComponent,
  {
    threatActorIndividual: graphql`
      fragment ThreatActorIndividualLocations_locations on ThreatActorIndividual {
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

export default compose(inject18n)(ThreatActorIndividualLocations);
