import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer, graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { KeyboardArrowRight } from '@mui/icons-material';
import Checkbox from '@mui/material/Checkbox';
import Skeleton from '@mui/material/Skeleton';
import { ListItemButton } from '@mui/material';
import inject18n from '../../../../components/i18n';
import ItemPatternType from '../../../../components/ItemPatternType';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import ItemMarkings from '../../../../components/ItemMarkings';
import ItemIcon from '../../../../components/ItemIcon';

const styles = (theme) => ({
  item: {
    paddingLeft: theme.spacing(1.5),
    height: 50,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: theme.spacing(1.5),
  },
  goIcon: {
    position: 'absolute',
    right: theme.spacing(-1.5),
  },
  itemIconDisabled: {
    color: theme.palette.grey[700],
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.grey[700],
  },
});

class StixDomainObjectIndicatorLineComponent extends Component {
  render() {
    const {
      fsd,
      classes,
      dataColumns,
      node,
      onToggleEntity,
      selectedElements,
      deSelectedElements,
      selectAll,
      onToggleShiftEntity,
      index,
    } = this.props;
    return (
      <ListItemButton
        key={node.id}
        classes={{ root: classes.item }}
        divider={true}
        component={Link}
        to={`/dashboard/observations/indicators/${node.id}`}
      >
        <ListItemIcon
          classes={{ root: classes.itemIcon }}
          style={{ minWidth: 40 }}
          onClick={(event) => (event.shiftKey
            ? onToggleShiftEntity(index, node, event)
            : onToggleEntity(node, event))
          }
        >
          <Checkbox
            edge="start"
            checked={
              (selectAll && !(node.id in (deSelectedElements || {})))
              || node.id in (selectedElements || {})
            }
            disableRipple={true}
          />
        </ListItemIcon>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type="Indicator" />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.pattern_type.width }}
              >
                <ItemPatternType variant="inList" label={node.pattern_type} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {node.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                <StixCoreObjectLabels
                  variant="inList"
                  labels={node.objectLabel}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                {fsd(node.created_at)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.valid_until.width }}
              >
                {fsd(node.valid_until)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                <ItemMarkings
                  variant="inList"
                  markingDefinitionsEdges={node.objectMarking.edges}
                  limit={1}
                />
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon>
      </ListItemButton>
    );
  }
}

StixDomainObjectIndicatorLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  entityId: PropTypes.string,
  paginationOptions: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fsd: PropTypes.func,
  onToggleEntity: PropTypes.func,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
};

const StixDomainObjectIndicatorLineFragment = createFragmentContainer(
  StixDomainObjectIndicatorLineComponent,
  {
    node: graphql`
      fragment StixDomainObjectIndicatorLine_node on Indicator {
        id
        entity_type
        name
        pattern_type
        description
        valid_from
        valid_until
        created
        created_at
        x_opencti_score
        x_opencti_main_observable_type
        objectMarking {
          edges {
            node {
              id
              definition_type
              definition
              x_opencti_order
              x_opencti_color
            }
          }
        }
        objectLabel {
          edges {
            node {
              id
              value
              color
            }
          }
        }
      }
    `,
  },
);

export const StixDomainObjectIndicatorLine = compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectIndicatorLineFragment);

class StixDomainObjectIndicatorLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon
          classes={{ root: classes.itemIconDisabled }}
          style={{ minWidth: 40 }}
        >
          <Checkbox edge="start" disabled={true} disableRipple={true} />
        </ListItemIcon>
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
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.pattern_type.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.valid_until.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width="90%"
                  height="100%"
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                <Skeleton
                  animation="wave"
                  variant="rectangular"
                  width={80}
                  height="100%"
                />
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <KeyboardArrowRight />
        </ListItemIcon>
      </ListItem>
    );
  }
}

StixDomainObjectIndicatorLineDummyComponent.propTypes = {
  classes: PropTypes.object,
  dataColumns: PropTypes.object,
};

export const StixDomainObjectIndicatorLineDummy = compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectIndicatorLineDummyComponent);
