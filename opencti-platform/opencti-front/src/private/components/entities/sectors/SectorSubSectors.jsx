import React from 'react';
import { filter } from 'ramda';
import Typography from '@mui/material/Typography';
import IconButton from '@common/button/IconButton';
import { Domain, LinkOff } from '@mui/icons-material';
import { graphql, createFragmentContainer } from 'react-relay';
import { AutoFix } from 'mdi-material-ui';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import { ListItemButton } from '@mui/material';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import AddSubSector from './AddSubSector';
import { addSubSectorsMutationRelationDelete } from './AddSubSectorsLines';
import { commitMutation } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';

const SectorSubSectorsComponent = ({ sector }) => {
  const { t_i18n } = useFormatter();

  const removeSubSector = (subSectorEdge) => {
    commitMutation({
      mutation: addSubSectorsMutationRelationDelete,
      variables: {
        fromId: subSectorEdge.node.id,
        toId: sector.id,
        relationship_type: 'part-of',
      },
      updater: (store) => {
        const node = store.get(sector.id);
        const subSectors = node.getLinkedRecord('subSectors');
        const edges = subSectors.getLinkedRecords('edges');
        const newEdges = filter(
          (n) => n.getLinkedRecord('node').getValue('id') !== subSectorEdge.node.id,
          edges,
        );
        subSectors.setLinkedRecords(newEdges, 'edges');
      },
    });
  };

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h3" gutterBottom={true} style={{ float: 'left' }}>
        {t_i18n('Subsectors')}
      </Typography>
      <Security needs={[KNOWLEDGE_KNUPDATE]}>
        <AddSubSector
          sector={sector}
          sectorSubSectors={sector.subSectors.edges}
        />
      </Security>
      <div className="clearfix" />
      {sector.subSectors.edges.map((subSectorEdge) => {
        const { types } = subSectorEdge;
        const subSector = subSectorEdge.node;
        return (
          <ListItem
            key={subSector.id}
            dense={true}
            divider={true}
            disablePadding
            secondaryAction={types.includes('manual') ? (
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <IconButton
                  aria-label="Remove"
                  onClick={() => removeSubSector(subSectorEdge)}
                >
                  <LinkOff />
                </IconButton>
              </Security>
            ) : <AutoFix fontSize="small" style={{ marginRight: 13 }} />}
          >
            <ListItemButton
              component={Link}
              to={`/dashboard/entities/sectors/${subSector.id}`}
            >
              <ListItemIcon>
                <Domain color="primary" />
              </ListItemIcon>
              <ListItemText primary={subSector.name} />
            </ListItemButton>
          </ListItem>
        );
      })}
    </div>
  );
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

export default SectorSubSectors;
