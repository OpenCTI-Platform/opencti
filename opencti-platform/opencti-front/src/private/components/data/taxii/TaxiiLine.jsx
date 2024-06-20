import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert } from '@mui/icons-material';
import { DatabaseExportOutline } from 'mdi-material-ui';
import { compose } from 'ramda';
import Slide from '@mui/material/Slide';
import Skeleton from '@mui/material/Skeleton';
import TaxiiPopover from './TaxiiPopover';
import inject18n from '../../../../components/i18n';
import FilterIconButton from '../../../../components/FilterIconButton';
import ItemCopy from '../../../../components/ItemCopy';
import { deserializeFilterGroupForFrontend } from '../../../../utils/filters/filtersUtils';
import { TAXIIAPI_SETCOLLECTIONS } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';

const Transition = React.forwardRef((props, ref) => (
  <Slide direction="up" ref={ref} {...props} />
));
Transition.displayName = 'TransitionSlide';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 40,
    display: 'flex',
    alignItems: 'center',
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  filtersItem: {
    height: 40,
    display: 'flex',
    alignItems: 'center',
    float: 'left',
    paddingRight: 10,
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
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
  filter: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    marginRight: 7,
    borderRadius: 10,
  },
  operator: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    height: 20,
    marginRight: 10,
  },
});

class TaxiiLineLineComponent extends Component {
  render() {
    const { classes, node, dataColumns, paginationOptions } = this.props;
    const filters = deserializeFilterGroupForFrontend(node.filters);
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component="a"
        href={`/taxii2/root/collections/${node.id}/objects`}
        target={'_blank'} // open in new tab
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <DatabaseExportOutline />
        </ListItemIcon>
        <ListItemText
          primary={
            <>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {node.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.description.width }}
              >
                {node.description}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.id.width, paddingRight: 10 }}
              >
                <ItemCopy content={node.id} variant="inLine" />
              </div>
              <div
                className={classes.filtersItem}
                style={{ width: dataColumns.filters.width }}
              >
                <FilterIconButton
                  filters={filters}
                  dataColumns={dataColumns}
                  styleNumber={3}
                />
              </div>
            </>
          }
        />
        <ListItemSecondaryAction>
          <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
            <TaxiiPopover
              taxiiCollectionId={node.id}
              paginationOptions={paginationOptions}
            />
          </Security>
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

TaxiiLineLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const TaxiiLineFragment = createFragmentContainer(TaxiiLineLineComponent, {
  node: graphql`
    fragment TaxiiLine_node on TaxiiCollection {
      id
      name
      description
      filters
    }
  `,
});

export const TaxiiLine = compose(
  inject18n,
  withStyles(styles),
)(TaxiiLineFragment);

class TaxiiDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={
            <>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.description.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.id.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.filters.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </div>
            </>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
          <MoreVert />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

TaxiiDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const TaxiiLineDummy = compose(
  inject18n,
  withStyles(styles),
)(TaxiiDummyComponent);
