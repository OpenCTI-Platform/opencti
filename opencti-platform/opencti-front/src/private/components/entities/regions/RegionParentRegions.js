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

class RegionParentRegionsComponent extends Component {
  render() {
    const { t, classes, region } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Parent regions')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <List>
            {region.parentRegions.edges.map((parentRegionEdge) => {
              const parentRegion = parentRegionEdge.node;
              return (
                <ListItem
                  key={parentRegion.id}
                  dense={true}
                  divider={true}
                  button={true}
                  component={Link}
                  to={`/dashboard/entities/regions/${parentRegion.id}`}
                >
                  <ListItemIcon>
                    <LocalPlayOutlined color="primary" />
                  </ListItemIcon>
                  <ListItemText
                    primary={parentRegion.name}
                    secondary={truncate(parentRegion.description, 50)}
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

RegionParentRegionsComponent.propTypes = {
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  attackPattern: PropTypes.object,
};

const RegionParentRegions = createFragmentContainer(
  RegionParentRegionsComponent,
  {
    region: graphql`
      fragment RegionParentRegions_region on Region {
        id
        parentRegions {
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

export default compose(inject18n, withStyles(styles))(RegionParentRegions);
