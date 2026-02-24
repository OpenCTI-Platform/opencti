import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { ListItemButton } from '@mui/material';
import { MoreVert, Stream } from '@mui/icons-material';
import { compose } from 'ramda';
import Slide from '@mui/material/Slide';
import Skeleton from '@mui/material/Skeleton';
import StreamPopover from './StreamPopover';
import inject18n from '../../../../components/i18n';
import FilterIconButton from '../../../../components/FilterIconButton';
import { deserializeFilterGroupForFrontend, isFilterGroupNotEmpty } from '../../../../utils/filters/filtersUtils';
import ItemCopy from '../../../../components/ItemCopy';
import ItemBoolean from '../../../../components/ItemBoolean';
import Security from '../../../../utils/Security';
import { TAXIIAPI_SETCOLLECTIONS } from '../../../../utils/hooks/useGranted';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { EMPTY_VALUE } from '../../../../utils/String';

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
  consumersItem: {
    height: 40,
    display: 'flex',
    alignItems: 'center',
    float: 'left',
    paddingRight: 10,
    gap: 8,
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
  constructor(props) {
    super(props);
    this.state = {
      displayConsumers: false,
    };
  }

  handleOpenConsumers() {
    this.setState({ displayConsumers: true });
  }

  handleCloseConsumers() {
    this.setState({ displayConsumers: false });
  }

  computeConsumersHealth() {
    const { node, t } = this.props;
    const { consumers } = node;
    if (!consumers || consumers.length === 0) {
      return { count: 0, label: t('No consumers'), hexColor: null };
    }
    const ONE_HOUR = 3600;
    const ONE_DAY = 86400;
    const hasCritical = consumers.some((c) => c.estimatedOutOfDepth !== null && c.estimatedOutOfDepth > 0 && c.estimatedOutOfDepth < ONE_HOUR);
    const hasWarning = consumers.some((c) => c.estimatedOutOfDepth !== null && c.estimatedOutOfDepth >= ONE_HOUR && c.estimatedOutOfDepth < ONE_DAY);
    if (hasCritical) {
      return { count: consumers.length, label: `${consumers.length} - ${t('At risk')}`, hexColor: '#c62828' };
    }
    if (hasWarning) {
      return { count: consumers.length, label: `${consumers.length} - ${t('Degraded')}`, hexColor: '#d84315' };
    }
    return { count: consumers.length, label: `${consumers.length} - ${t('Healthy')}`, hexColor: '#2e7d32' };
  }

  render() {
    const { classes, node, dataColumns, paginationOptions, t } = this.props;
    const _health = this.computeConsumersHealth();
    const filters = deserializeFilterGroupForFrontend(node.filters);
    return (
      <ListItem
        divider={true}
        disablePadding
        secondaryAction={(
          <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
            <StreamPopover
              streamCollection={node}
              paginationOptions={paginationOptions}
            />
          </Security>
        )}
      >
        <ListItemButton
          classes={{ root: classes.item }}
          component="a"
          href={`/stream/${node.id}`}
          target="_blank"
        >
          <ListItemIcon classes={{ root: classes.itemIcon }}>
            <Stream />
          </ListItemIcon>
          <ListItemText
            primary={(
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
                  <FieldOrEmpty source={node.description}>{node.description}</FieldOrEmpty>
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
                  className={classes.consumersItem}
                  style={{ width: dataColumns.consumers.width }}
                >
                  {isFilterGroupNotEmpty(filters)
                    ? (
                        <FilterIconButton
                          filters={filters}
                          dataColumns={dataColumns}
                          variant="small"
                          entityTypes={['Stix-Filtering']}
                        />
                      )
                    : EMPTY_VALUE
                  }
                </div>
              </>
            )}
          />
        </ListItemButton>
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
      consumers {
        connectionId
        estimatedOutOfDepth
      }
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
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        secondaryAction={<MoreVert classes={classes.itemIconDisabled} />}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Skeleton
            animation="wave"
            variant="circular"
            width={30}
            height={30}
          />
        </ListItemIcon>
        <ListItemText
          primary={(
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
                style={{ width: dataColumns.consumers.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="50%"
                />
              </div>
            </div>
          )}
        />
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
