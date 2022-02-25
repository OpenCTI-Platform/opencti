import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Link } from 'react-router-dom';
import { LocalPlayOutlined } from '@mui/icons-material';
import { graphql, createFragmentContainer } from 'react-relay';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
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

class RegionSubRegionsComponent extends Component {
  render() {
    const { t, classes, region } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Subregions')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <List>
            {region.subRegions.edges.map((subRegionEdge) => {
              const subRegion = subRegionEdge.node;
              return (
                <ListItem
                  key={subRegion.id}
                  dense={true}
                  divider={true}
                  button={true}
                  component={Link}
                  to={`/dashboard/entities/regions/${subRegion.id}`}
                >
                  <ListItemIcon>
                    <LocalPlayOutlined color="primary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={subRegion.name}
                    secondary={truncate(subRegion.description, 50)}
                  />
                </ListItem>
              );
            })}
          </List>
        </Paper>
      </div>
    );
  }
}

RegionSubRegionsComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  region: PropTypes.object,
};

const RegionSubRegions = createFragmentContainer(RegionSubRegionsComponent, {
  region: graphql`
    fragment RegionSubRegions_region on Region {
      id
      subRegions {
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
});

export default compose(inject18n, withStyles(styles))(RegionSubRegions);
