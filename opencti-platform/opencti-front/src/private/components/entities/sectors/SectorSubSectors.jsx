import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter } from 'ramda';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ListItemButton, ListItem } from '@mui/material';
import { Link } from 'react-router-dom';
import IconButton from '@mui/material/IconButton';
import { Domain, LinkOff } from '@mui/icons-material';
import { graphql, createFragmentContainer } from 'react-relay';
import { AutoFix } from 'mdi-material-ui';
import AddSubSector from './AddSubSector';
import { addSubSectorsMutationRelationDelete } from './AddSubSectorsLines';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';

class SectorSubSectorsComponent extends Component {
  removeSubSector(subSectorEdge) {
    commitMutation({
      mutation: addSubSectorsMutationRelationDelete,
      variables: {
        fromId: subSectorEdge.node.id,
        toId: this.props.sector.id,
        relationship_type: 'part-of',
      },
      updater: (store) => {
        const node = store.get(this.props.sector.id);
        const subSectors = node.getLinkedRecord('subSectors');
        const edges = subSectors.getLinkedRecords('edges');
        const newEdges = filter(
          (n) => n.getLinkedRecord('node').getValue('id') !== subSectorEdge.node.id,
          edges,
        );
        subSectors.setLinkedRecords(newEdges, 'edges');
      },
    });
  }

  render() {
    const { t, sector } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
          {t('Subsectors')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <AddSubSector
            sector={sector}
            sectorSubSectors={sector.subSectors.edges}
          />
        </Security>
        <div className="clearfix" />
        <List style={{ marginTop: -10 }}>
          {sector.subSectors.edges.map((subSectorEdge) => {
            const { types } = subSectorEdge;
            const subSector = subSectorEdge.node;
            return (
              <ListItem
                key={subSector.id}
                dense={true}
                divider={true}
                secondaryAction={types.includes('manual') ? (
                  <Security needs={[KNOWLEDGE_KNUPDATE]}>
                    <IconButton
                      aria-label="Remove"
                      onClick={this.removeSubSector.bind(this, subSectorEdge)}
                      size="large"
                    >
                      <LinkOff />
                    </IconButton>
                  </Security>
                ) : <AutoFix fontSize="small" style={{ marginRight: 13 }}/>}
              >
                <ListItemButton component={Link} to={`/dashboard/entities/sectors/${subSector.id}`} >
                  <ListItemIcon>
                    <Domain color="primary" />
                  </ListItemIcon>
                  <ListItemText primary={subSector.name} />
                </ListItemButton>
              </ListItem>
            );
          })}
        </List>
      </div>
    );
  }
}

SectorSubSectorsComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  sector: PropTypes.object,
};

const SectorSubSectors = createFragmentContainer(SectorSubSectorsComponent, {
  sector: graphql`
    fragment SectorSubSectors_sector on Sector {
      id
      name
      parent_types
      entity_type
      subSectors {
        edges {
          types
          node {
            id
            name
            description
            parent_types
          }
        }
      }
    }
  `,
});

export default compose(inject18n)(SectorSubSectors);
