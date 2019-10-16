import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { Link } from 'react-router-dom';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import { MoreVert } from '@material-ui/icons';
import { HexagonOutline } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';
import ItemConfidenceLevel from '../../../components/ItemConfidenceLevel';
import StixRelationPopover from '../common/stix_relations/StixRelationPopover';
import { resolveLink } from '../../../utils/Entity';

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

class StixObservableEntityLineComponent extends Component {
  render() {
    const {
      nsd,
      t,
      classes,
      dataColumns,
      node,
      paginationOptions,
    } = this.props;
    const link = `${resolveLink(node.to.entity_type)}/${
      node.to.id
    }/observables/relations/${node.id}`;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={link}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <HexagonOutline />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.entity_type.width }}
              >
                {t(`entity_${node.to.entity_type}`)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.name.width }}
              >
                {node.to.name}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.role_played.width }}
              >
                {/* eslint-disable-next-line no-nested-ternary */}
                {node.inferred
                  ? '-'
                  : node.role_played
                    ? t(node.role_played)
                    : t('Unknown')}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.first_seen.width }}
              >
                {node.inferred ? '-' : nsd(node.first_seen)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_seen.width }}
              >
                {node.inferred ? '-' : nsd(node.last_seen)}
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.weight.width }}
              >
                <ItemConfidenceLevel
                  level={node.inferred ? 99 : node.weight}
                  variant="inList"
                />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <StixRelationPopover
            stixRelationId={node.id}
            paginationOptions={paginationOptions}
            disabled={node.inferred}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

StixObservableEntityLineComponent.propTypes = {
  dataColumns: PropTypes.object,
  paginationOptions: PropTypes.object,
  node: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

const StixObservableEntityLineFragment = createFragmentContainer(
  StixObservableEntityLineComponent,
  {
    node: graphql`
      fragment StixObservableEntityLine_node on StixRelation {
        id
        weight
        first_seen
        last_seen
        description
        role_played
        inferred
        to {
          ... on StixDomainEntity {
            id
            entity_type
            name
            description
            created_at
            updated_at
          }
        }
      }
    `,
  },
);

export const StixObservableEntityLine = compose(
  inject18n,
  withStyles(styles),
)(StixObservableEntityLineFragment);

class StixObservableEntityLineDummyComponent extends Component {
  render() {
    const { classes, dataColumns } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <HexagonOutline />
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
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.role_played.width }}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.first_seen.width }}
              >
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.last_seen.width }}
              >
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div
                className={classes.bodyItem}
                style={{ width: dataColumns.weight.width }}
              >
                <div className="fakeItem" style={{ width: 100 }} />
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

StixObservableEntityLineDummyComponent.propTypes = {
  dataColumns: PropTypes.object,
  classes: PropTypes.object,
};

export const StixObservableEntityLineDummy = compose(
  inject18n,
  withStyles(styles),
)(StixObservableEntityLineDummyComponent);
