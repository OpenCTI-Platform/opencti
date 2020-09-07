import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Checkbox from '@material-ui/core/Checkbox';
import { compose, pathOr, take } from 'ramda';
import inject18n from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import StixCoreObjectLabels from '../../common/stix_core_objects/StixCoreObjectLabels';

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

class CurationStixDomainObjectLineComponent extends Component {
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
    } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        onClick={onToggleEntity.bind(this, node)}
        selected={node.id in selectedElements}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Checkbox
            edge="start"
            checked={node.id in selectedElements}
            disableRipple={true}
            onChange={onToggleEntity.bind(this, node)}
          />
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
                {node.name || node.attribute_abstract || node.opinion}
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
                {take(1, pathOr([], ['objectMarking', 'edges'], node)).map(
                  (markingDefinition) => (
                    <ItemMarking
                      key={markingDefinition.node.id}
                      variant="inList"
                      label={markingDefinition.node.definition}
                    />
                  ),
                )}
              </div>
            </div>
          }
        />
      </ListItem>
    );
  }
}

CurationStixDomainObjectLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
  onLabelClick: PropTypes.func,
  onToggleEntity: PropTypes.func,
  selectedElements: PropTypes.object,
};

const CurationStixDomainObjectLineFragment = createFragmentContainer(
  CurationStixDomainObjectLineComponent,
  {
    node: graphql`
      fragment CurationStixDomainObjectLine_node on StixDomainObject {
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
        ... on XOpenCTIIncident {
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

export const CurationStixDomainObjectLine = compose(
  inject18n,
  withStyles(styles),
)(CurationStixDomainObjectLineFragment);

class CurationStixDomainObjectLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Checkbox edge="start" disabled={true} disableRipple={true} />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <div className="fakeItem" style={{ width: '70%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.createdBy.width }}
              >
                <div className="fakeItem" style={{ width: '70%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectLabel.width }}
              >
                <div className="fakeItem" style={{ width: '90%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.created_at.width }}
              >
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.objectMarking.width }}
              >
                <div className="fakeItem" style={{ width: 100 }} />
              </div>
            </div>
          }
        />
      </ListItem>
    );
  }
}

CurationStixDomainObjectLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const CurationStixDomainObjectLineDummy = compose(
  inject18n,
  withStyles(styles),
)(CurationStixDomainObjectLineDummyComponent);
