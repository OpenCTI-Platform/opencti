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
import { MoreVert, Help } from '@material-ui/icons';
import { Tag } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';
import ItemConfidenceLevel from '../../../components/ItemConfidenceLevel';
import StixRelationPopover from '../common/stix_relations/StixRelationPopover';
import { resolveLink } from '../../../utils/Entity';

const styles = theme => ({
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  bodyItem: {
    height: '100%',
    fontSize: 13,
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

const inlineStyles = {
  entity_type: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  name: {
    float: 'left',
    width: '22%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  role_played: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  first_seen: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  last_seen: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  weight: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class StixObservableEntityLineComponent extends Component {
  render() {
    const {
      nsd,
      t,
      classes,
      stixRelation,
      stixDomainEntity,
      paginationOptions,
    } = this.props;
    const link = `${resolveLink(stixDomainEntity.entity_type)}/${
      stixDomainEntity.id
    }/observables/relations/${stixRelation.id}`;
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={link}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <Tag />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.entity_type}
              >
                {t(`entity_${stixDomainEntity.entity_type}`)}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                {stixDomainEntity.name}
              </div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.role_played}
              >
                {stixRelation.inferred ? '-' : stixRelation.role_played ? t(stixRelation.role_played) : t('Unknown')}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.first_seen}>
                {stixRelation.inferred ? '-' : nsd(stixRelation.first_seen)}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.last_seen}>
                {stixRelation.inferred ? '-' : nsd(stixRelation.last_seen)}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.weight}>
                <ItemConfidenceLevel
                  level={stixRelation.inferred ? 99 : stixRelation.weight}
                  variant="inList"
                />
              </div>
            </div>
          }
        />
        <ListItemSecondaryAction>
          <StixRelationPopover
            stixRelationId={stixRelation.id}
            paginationOptions={paginationOptions}
            disabled={stixRelation.inferred}
          />
        </ListItemSecondaryAction>
      </ListItem>
    );
  }
}

StixObservableEntityLineComponent.propTypes = {
  entityId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  stixRelation: PropTypes.object,
  stixDomainEntity: PropTypes.object,
  stixObservable: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

const StixObservableEntityLineFragment = createFragmentContainer(
  StixObservableEntityLineComponent,
  {
    stixRelation: graphql`
      fragment StixObservableEntityLine_stixRelation on StixRelation {
        id
        weight
        first_seen
        last_seen
        description
        role_played
        inferred
      }
    `,
    stixDomainEntity: graphql`
      fragment StixObservableEntityLine_stixDomainEntity on StixDomainEntity {
        id
        entity_type
        name
        description
        created_at
        updated_at
      }
    `,
    stixObservable: graphql`
      fragment StixObservableEntityLine_stixObservable on StixObservable {
        id
        entity_type
        observable_value
        description
        created_at
        updated_at
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
    const { classes } = this.props;
    return (
      <ListItem classes={{ root: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Help />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.entity_type}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.role_played}
              >
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.first_seen}>
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.last_seen}>
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.weight}>
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
  classes: PropTypes.object,
};

export const StixObservableEntityLineDummy = compose(
  inject18n,
  withStyles(styles),
)(StixObservableEntityLineDummyComponent);
