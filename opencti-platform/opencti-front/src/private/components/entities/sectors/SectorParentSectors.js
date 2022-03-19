import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import { Domain } from '@mui/icons-material';
import { graphql, createFragmentContainer } from 'react-relay';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';

class SectorParentSectorsComponent extends Component {
  render() {
    const { t, sector } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Parent sectors')}
        </Typography>
        <List>
          {sector.parentSectors.edges.map((parentSectorEdge) => {
            const parentSector = parentSectorEdge.node;
            return (
              <ListItem
                key={parentSector.id}
                dense={true}
                divider={true}
                button={true}
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
              </ListItem>
            );
          })}
        </List>
      </div>
    );
  }
}

SectorParentSectorsComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
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

export default compose(inject18n)(SectorParentSectors);
