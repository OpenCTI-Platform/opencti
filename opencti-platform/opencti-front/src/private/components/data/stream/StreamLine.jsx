import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import { MoreVert, Stream } from '@mui/icons-material';
import { compose } from 'ramda';
import Slide from '@mui/material/Slide';
import Skeleton from '@mui/material/Skeleton';
import StreamPopover from './StreamPopover';
import inject18n from '../../../../components/i18n';
import FilterIconButton from '../../../../components/FilterIconButton';
import ItemCopy from '../../../../components/ItemCopy';
import ItemBoolean from '../../../../components/ItemBoolean';
import { deserializeFilterGroupForFrontend } from '../../../../utils/filters/filtersUtils';
import Security from '../../../../utils/Security';
import { TAXIIAPI_SETCOLLECTIONS } from '../../../../utils/hooks/useGranted';

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
  chipInList: {
    fontSize: 12,
    height: 20,
    maxWidth: 120,
    display: 'table-cell',
  },
});

class StreamLineLineComponent extends Component {
  render() {
    const { classes, node, dataColumns, paginationOptions, t } = this.props;
    const filters = deserializeFilterGroupForFrontend(node.filters);
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component="a"
        href={`/stream/${node.id}`}
        target={'_blank'} // open in new tab
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Stream />
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
                className={classes.bodyItem}
                style={{ width: dataColumns.stream_public.width }}
              >
                <ItemBoolean
                  variant="inList"
                  label={node.stream_public ? t('Yes') : t('No')}
                  status={node.stream_public}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.stream_live.width }}
              >
                <ItemBoolean
                  variant="inList"
                  label={node.stream_live ? t('Started') : t('Stopped')}
                  status={node.stream_live}
                />
              </div>
              <div
                className={classes.filtersItem}
                style={{ width: dataColumns.filters.width }}
              >
                <FilterIconButton
                  filters={filters}
                  dataColumns={dataColumns}
                  styleNumber={3}
                  entityTypes={['Stix-Filtering']}
                />
              </div>
            </>
          }
        />
        <ListItemSecondaryAction>
          <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
            <StreamPopover
              streamCollection={node}
              paginationOptions={paginationOptions}
            />
          </Security>
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

StreamLineLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  paginationOptions: PropTypes.object,
  me: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
};

const StreamLineFragment = createFragmentContainer(StreamLineLineComponent, {
  node: graphql`
    fragment StreamLine_node on StreamCollection {
      id
      name
      description
      filters
      stream_public
      stream_live
      ...StreamCollectionEdition_streamCollection
    }
  `,
});

export const StreamLine = compose(
  inject18n,
  withStyles(styles),
)(StreamLineFragment);

class StreamDummyComponent extends Component {
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
            <div>
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
                style={{ width: dataColumns.stream_public.width }}
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
                style={{ width: dataColumns.stream_live.width }}
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
            </div>
          }
        />
        <ListItemSecondaryAction classes={{ root: classes.itemIconDisabled }}>
          <MoreVert />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

StreamDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const StreamLineDummy = compose(
  inject18n,
  withStyles(styles),
)(StreamDummyComponent);
