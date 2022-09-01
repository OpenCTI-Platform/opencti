import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Checkbox from '@mui/material/Checkbox';
import { compose, pathOr } from 'ramda';
import Skeleton from '@mui/material/Skeleton';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import IconButton from '@mui/material/IconButton';
import { Link } from 'react-router-dom';
import { VisibilityOutlined } from '@mui/icons-material';
import inject18n from '../../../../components/i18n';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';
import { truncate } from '../../../../utils/String';
import ItemIcon from '../../../../components/ItemIcon';
import ItemMarkings from '../../../../components/ItemMarkings';
import { resolveLink } from '../../../../utils/Entity';

const styles = (theme) => ({
  item: {
    paddingLeft: 10,
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
    paddingRight: 5,
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
});

class EntitiesStixDomainObjectLineComponent extends Component {
  render() {
    const {
      t,
      fd,
      classes,
      dataColumns,
      node,
      onLabelClick,
      onToggleEntity,
      selectedElements,
      deSelectedElements,
      selectAll,
    } = this.props;
    const link = `${resolveLink(node.entity_type)}/${node.id}`;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        onClick={onToggleEntity.bind(this, node)}
        selected={node.id in (selectedElements || {})}
      >
        <ListItemIcon
          classes={{ root: classes.itemIcon }}
          style={{ minWidth: 40 }}
        >
          <Checkbox
            edge="start"
            checked={
              (selectAll && !(node.id in (deSelectedElements || {})))
              || node.id in (selectedElements || {})
            }
            disableRipple={true}
            onChange={onToggleEntity.bind(this, node)}
          />
        </ListItemIcon>
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type={node.entity_type} />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                {t(`entity_${node.entity_type}`)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {node.name
                  || node.attribute_abstract
                  || truncate(node.content, 30)
                  || node.opinion}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.createdBy.width }}
              >
                {pathOr('', ['createdBy', 'name'], node)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                <StixCoreObjectLabels
                  variant="inList"
                  labels={node.objectLabel}
                  onClick={onLabelClick.bind(this)}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                {fd(node.created_at)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                <ItemMarkings
                  markingDefinitions={pathOr(
                    [],
                    ['objectMarking', 'edges'],
                    node,
                  )}
                  limit={1}
                  variant="inList"
                />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <IconButton
            aria-label="Go to"
            component={Link}
            to={link}
            size="large"
          >
            <VisibilityOutlined />
          </IconButton>
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

EntitiesStixDomainObjectLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
  onLabelClick: PropTypes.func,
  onToggleEntity: PropTypes.func,
  selectedElements: PropTypes.object,
  deSelectedElements: PropTypes.object,
};

const EntitiesStixDomainObjectLineFragment = createFragmentContainer(
  EntitiesStixDomainObjectLineComponent,
  {
    node: graphql`
      fragment EntitiesStixDomainObjectLine_node on StixDomainObject {
        id
        entity_type
        created_at
        ... on AttackPattern {
          name
          description
          aliases
        }
        ... on Campaign {
          name
          description
          aliases
        }
        ... on Note {
          attribute_abstract
          content
        }
        ... on ObservedData {
          name
          first_observed
          last_observed
        }
        ... on Opinion {
          opinion
          explanation
        }
        ... on Report {
          name
          description
        }
        ... on CourseOfAction {
          name
          description
          x_opencti_aliases
        }
        ... on Individual {
          name
          description
          x_opencti_aliases
        }
        ... on Organization {
          name
          description
          x_opencti_aliases
        }
        ... on Sector {
          name
          description
          x_opencti_aliases
        }
        ... on System {
          name
          description
          x_opencti_aliases
        }
        ... on Indicator {
          name
          description
        }
        ... on Infrastructure {
          name
          description
        }
        ... on IntrusionSet {
          name
          aliases
          description
        }
        ... on Position {
          name
          description
          x_opencti_aliases
        }
        ... on City {
          name
          description
          x_opencti_aliases
        }
        ... on Country {
          name
          description
          x_opencti_aliases
        }
        ... on Region {
          name
          description
          x_opencti_aliases
        }
        ... on Malware {
          name
          aliases
          description
        }
        ... on ThreatActor {
          name
          aliases
          description
        }
        ... on Tool {
          name
          aliases
          description
        }
        ... on Vulnerability {
          name
          description
        }
        ... on Incident {
          name
          aliases
          description
        }
        createdBy {
          ... on Identity {
            name
          }
        }
        objectMarking {
          edges {
            node {
              id
              definition
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
export const EntitiesStixDomainObjectLine = compose(
  inject18n,
  withStyles(styles),
)(EntitiesStixDomainObjectLineFragment);

class EntitiesStixDomainObjectLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        style={{ minWidth: 40 }}
      >
        <ListItemIcon
          classes={{ root: classes.itemIconDisabled }}
          style={{ minWidth: 40 }}
        >
          <Checkbox edge="start" disabled={true} disableRipple={true} />
        </ListItemIcon>
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
                style={{ width: dataColumns.entity_type.width }}
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
                style={{ width: dataColumns.createdBy.width }}
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
                  width={140}
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
                  width={100}
                  height="100%"
                />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <IconButton aria-label="Go to" component={Link} disabled={true} size="large">
            <VisibilityOutlined />
          </IconButton>
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

EntitiesStixDomainObjectLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const EntitiesStixDomainObjectLineDummy = compose(
  inject18n,
  withStyles(styles),
)(EntitiesStixDomainObjectLineDummyComponent);
