import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { KeyboardArrowRight } from '@material-ui/icons';
import { ShieldSearch } from 'mdi-material-ui';
import { compose, pathOr, take } from 'ramda';
import inject18n from '../../../../components/i18n';
import ItemMarking from '../../../../components/ItemMarking';
import ItemPatternType from '../../../../components/ItemPatternType';
import StixObjectTags from '../../common/stix_object/StixObjectTags';

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
    right: 10,
    marginRight: 0,
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

class IndicatorLineComponent extends Component {
  render() {
    const {
      fd, classes, dataColumns, node, onTagClick,
    } = this.props;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={`/dashboard/signatures/indicators/${node.id}`}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ShieldSearch />
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
                style={{ width: dataColumns.tags.width }}
              >
                <StixObjectTags
                  variant="inList"
                  tags={node.tags}
                  onClick={onTagClick.bind(this)}
                />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.valid_from.width }}
              >
                {fd(node.valid_from)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.valid_until.width }}
              >
                {fd(node.valid_until)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.markingDefinitions.width }}
              >
                {take(1, pathOr([], ['markingDefinitions', 'edges'], node)).map(
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
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon>
      </ListItem>
    );
  }
}

IndicatorLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  onTagClick: PropTypes.func,
};

const IndicatorLineFragment = createFragmentContainer(IndicatorLineComponent, {
  node: graphql`
    fragment IndicatorLine_node on Indicator {
      id
      name
      main_observable_type
      pattern_type
      valid_from
      valid_until
      score
      markingDefinitions {
        edges {
          node {
            id
            definition
          }
        }
      }
      tags {
        edges {
          node {
            id
            tag_type
            value
            color
          }
          relation {
            id
          }
        }
      }
    }
  `,
});

export const IndicatorLine = compose(
  inject18n,
  withStyles(styles),
)(IndicatorLineFragment);

class IndicatorLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <ShieldSearch />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.pattern_type.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.tags.width }}
              >
                <div className="fakeItem" style={{ width: '90%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.valid_from.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.valid_until.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.markingDefinitions.width }}
              >
                <div className="fakeItem" style={{ width: 100 }} />
              </div>
            </div>
          }
        />
        <ListItemIcon classes={{ root: classes.goIcon }}>
          <KeyboardArrowRight />
        </ListItemIcon>
      </ListItem>
    );
  }
}

IndicatorLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const IndicatorLineDummy = compose(
  inject18n,
  withStyles(styles),
)(IndicatorLineDummyComponent);
