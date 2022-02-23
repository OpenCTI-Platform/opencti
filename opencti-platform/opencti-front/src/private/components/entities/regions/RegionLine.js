import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import {
  KeyboardArrowRightOutlined,
  LocalPlayOutlined,
} from '@mui/icons-material';
import {
  compose,
  filter,
  map,
  pathOr,
  pipe,
  prop,
  sortBy,
  toLower,
  uniqBy,
  concat,
} from 'ramda';
import List from '@mui/material/List';
import Skeleton from '@mui/material/Skeleton';
import inject18n from '../../../../components/i18n';
import { CountryLine } from '../countries/CountryLine';

const styles = (theme) => ({
  item: {},
  itemNested: {
    paddingLeft: theme.spacing(4),
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  name: {
    width: '20%',
    height: 20,
    lineHeight: '20px',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  description: {
    width: '70%',
    height: 20,
    lineHeight: '20px',
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    color: '#a5a5a5',
  },
  goIcon: {
    position: 'absolute',
    right: -10,
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '.6em',
    backgroundColor: theme.palette.grey[700],
  },
});

class RegionLineComponent extends Component {
  render() {
    const { classes, subRegions, countries, node, isSubRegion, keyword } = this.props;
    const sortByNameCaseInsensitive = sortBy(compose(toLower, prop('name')));
    const filterByKeyword = (n) => keyword === ''
      || n.name.toLowerCase().indexOf(keyword.toLowerCase()) !== -1;
    return (
      <div>
        <ListItem
          classes={{ root: isSubRegion ? classes.itemNested : classes.item }}
          divider={true}
          button={true}
          component={Link}
          to={`/dashboard/entities/regions/${node.id}`}
        >
          <ListItemIcon classes={{ root: classes.itemIcon }}>
            <LocalPlayOutlined />
          </ListItemIcon>
          <ListItemText primary={node.name} />
          <ListItemIcon classes={{ root: classes.goIcon }}>
            <KeyboardArrowRightOutlined />
          </ListItemIcon>
        </ListItem>
        {subRegions && subRegions.length > 0 ? (
          <List style={{ margin: 0, padding: 0 }}>
            {subRegions.map((subRegion) => {
              const subRegionCountries = pipe(
                pathOr([], ['countries', 'edges']),
                map((n) => n.node),
                concat(countries),
                filter(filterByKeyword),
                uniqBy(prop('id')),
                sortByNameCaseInsensitive,
              )(subRegion);
              return (
                // eslint-disable-next-line @typescript-eslint/no-use-before-define
                <RegionLine
                  key={subRegion.id}
                  node={subRegion}
                  countries={subRegionCountries}
                  isSubRegion={true}
                />
              );
            })}
          </List>
        ) : (
          countries
          && countries.length > 0 && (
            <List style={{ margin: 0, padding: 0 }}>
              {countries.map((country) => (
                <CountryLine key={country.id} node={country} />
              ))}
            </List>
          )
        )}
      </div>
    );
  }
}

RegionLineComponent.propTypes = {
  node: PropTypes.object,
  isSubRegion: PropTypes.bool,
  subRegions: PropTypes.array,
  countries: PropTypes.array,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

export const RegionLine = compose(
  inject18n,
  withStyles(styles),
)(RegionLineComponent);

class RegionLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <Skeleton
              animation="wave"
              variant="rectangular"
              width="90%"
              height={20}
            />
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRightOutlined />
        </ListItemIcon>
      </ListItem>
    );
  }
}

RegionLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const RegionLineDummy = compose(
  inject18n,
  withStyles(styles),
)(RegionLineDummyComponent);
