import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, filter } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { Link } from 'react-router-dom';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import IconButton from '@material-ui/core/IconButton';
import { Domain, LinkOff } from '@material-ui/icons';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { truncate } from '../../../../utils/String';
import AddSubSector from './AddSubSector';
import { addSubSectorsMutationRelationDelete } from './AddSubSectorsLines';
import { commitMutation } from '../../../../relay/environment';
import inject18n from '../../../../components/i18n';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '-4px 0 0 0',
    padding: 0,
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
    backgroundColor: theme.palette.grey[700],
  },
});

class SectorSubSectorsComponent extends Component {
  removeSubSector(subSectorEdge) {
    commitMutation({
      mutation: addSubSectorsMutationRelationDelete,
      variables: {
        id: subSectorEdge.relation.id,
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
    const { t, classes, sector } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
          {t('Subsectors')}
        </Typography>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <AddSubSector
            sectorId={sector.id}
            sectorSubSectors={sector.subSectors.edges}
          />
        </Security>
        <div className="clearfix" />
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <List>
            {sector.subSectors.edges.map((subSectorEdge) => {
              const subSector = subSectorEdge.node;
              return (
                <ListItem
                  key={subSector.id}
                  dense={true}
                  divider={true}
                  button={true}
                  component={Link}
                  to={`/dashboard/entities/sectors/${subSector.id}`}
                >
                  <ListItemIcon>
                    <Domain color="primary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={subSector.name}
                    secondary={truncate(subSector.description, 50)}
                  />
                  <ListItemSecondaryAction>
                    <IconButton
                      aria-label="Remove"
                      onClick={this.removeSubSector.bind(this, subSectorEdge)}
                    >
                      <LinkOff />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              );
            })}
          </List>
        </Paper>
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
      subSectors {
        edges {
          node {
            id
            name
            description
          }
          relation {
            id
          }
        }
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(SectorSubSectors);
