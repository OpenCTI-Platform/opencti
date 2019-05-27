import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Typography from '@material-ui/core/Typography';
import { Domain } from '@material-ui/icons';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '5px 0 10px 0',
    borderRadius: 6,
  },
  item: {
    paddingLeft: 15,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
});

class SectorSubsectorsComponent extends Component {
  render() {
    const { t, classes, sector } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Subsectors')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <List>
            {sector.subsectors.edges.map((subsectorEdge) => {
              const subsector = subsectorEdge.node;
              return (
                <ListItem
                  key={subsector.id}
                  dense={true}
                  divider={true}
                  classes={{ root: classes.item }}
                  button={true}
                  component={Link}
                  to={`/dashboard/knowledge/sectors/${subsector.id}`}
                >
                  <ListItemIcon classes={{ root: classes.itemIcon }}>
                    <Domain />
                  </ListItemIcon>
                  <ListItemText primary={subsector.name} />
                </ListItem>
              );
            })}
          </List>
        </Paper>
      </div>
    );
  }
}

SectorSubsectorsComponent.propTypes = {
  sector: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const SectorSubsectors = createFragmentContainer(SectorSubsectorsComponent, {
  sector: graphql`
    fragment SectorSubsectors_sector on Sector {
      id
      subsectors {
        edges {
          node {
            id
            name
          }
        }
      }
    }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(SectorSubsectors);
