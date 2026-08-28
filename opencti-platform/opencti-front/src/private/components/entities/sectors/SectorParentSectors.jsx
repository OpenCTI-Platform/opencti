import React from 'react';
import * as PropTypes from 'prop-types';
import List from '@mui/material/List';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ListItemButton } from '@mui/material';
import { Link } from 'react-router-dom';
import { Domain } from '@mui/icons-material';
import { graphql, createFragmentContainer } from 'react-relay';
import { truncate } from '../../../../utils/String';
import { useFormatter } from '../../../../components/i18n';
import Label from '../../../../components/common/label/Label';

const SectorParentSectorsComponent = (props) => {
  const { t_i18n } = useFormatter();
  const { sector } = props;
  return (
    <div style={{ height: '100%' }}>
      <Label>
        {t_i18n('Parent sectors')}
      </Label>
      <List sx={{ py: 0 }}>
        {sector.parentSectors.edges.map((parentSectorEdge) => {
          const parentSector = parentSectorEdge.node;
          return (
            <ListItemButton
              key={parentSector.id}
              dense={true}
              divider={true}
              component={Link}
              to={`/dashboard/entities/sectors/${parentSector.id}`}
            >
              <ListItemIcon>
                <Domain color="primary" />
              </ListItemIcon>
              <ListItemText
                primary={parentSector.name}
                secondary={truncate(parentSector.description, 50)}
              />
            </ListItemButton>
          );
        })}
      </List>
    </div>
  );
};

SectorParentSectorsComponent.propTypes = {
  classes: PropTypes.object,
  attackPattern: PropTypes.object,
};

const SectorParentSectors = createFragmentContainer(
  SectorParentSectorsComponent,
  {
    sector: graphql`
      fragment SectorParentSectors_sector on Sector {
        id
        parentSectors {
          edges {
            node {
              id
              name
              description
            }
          }
        }
      }
    `,
  },
);

export default SectorParentSectors;
