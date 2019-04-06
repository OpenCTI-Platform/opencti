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
import inject18n from '../../../components/i18n';
import ItemIcon from '../../../components/ItemIcon';
import ItemConfidenceLevel from '../../../components/ItemConfidenceLevel';
import { resolveLink } from '../../../utils/Entity';
import StixRelationPopover from './StixRelationPopover';

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
    color: theme.palette.text.disabled,
  },
  placeholder: {
    display: 'inline-block',
    height: '1em',
    backgroundColor: theme.palette.text.disabled,
  },
});

const inlineStyles = {
  name: {
    float: 'left',
    width: '30%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  entity_type: {
    float: 'left',
    width: '20%',
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

class ReportLineComponent extends Component {
  render() {
    const {
      nsd,
      t,
      classes,
      stixRelation,
      stixDomainEntity,
      stixDomainEntityFrom,
      paginationOptions,
      entityId,
      entityLink,
    } = this.props;
    let link = `${entityLink}/relations/${stixRelation.id}`;
    if (stixDomainEntityFrom.id !== entityId) {
      link = `${resolveLink(stixDomainEntityFrom.entity_type)}/${
        stixDomainEntityFrom.id
      }/knowledge/relations/${stixRelation.id}`;
    }
    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        button={true}
        component={Link}
        to={link}
      >
        <ListItemIcon classes={{ root: classes.itemIcon }}>
          <ItemIcon type={stixDomainEntity.entity_type} />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                {stixDomainEntity.name}
              </div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.entity_type}
              >
                {t(`entity_${stixDomainEntity.entity_type}`)}
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

ReportLineComponent.propTypes = {
  entityId: PropTypes.string,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  stixRelation: PropTypes.object,
  stixDomainEntity: PropTypes.object,
  stixDomainEntityFrom: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

const ReportLineFragment = createFragmentContainer(ReportLineComponent, {
  stixRelation: graphql`
    fragment EntityStixRelationLine_stixRelation on StixRelation {
      id
      weight
      first_seen
      last_seen
      description
      inferred
    }
  `,
  stixDomainEntity: graphql`
    fragment EntityStixRelationLine_stixDomainEntity on StixDomainEntity {
      id
      entity_type
      name
      description
      created_at
      updated_at
    }
  `,
  stixDomainEntityFrom: graphql`
    fragment EntityStixRelationLine_stixDomainEntityFrom on StixDomainEntity {
      id
      entity_type
      name
      description
      created_at
      updated_at
    }
  `,
});

export const EntityStixRelationLine = compose(
  inject18n,
  withStyles(styles),
)(ReportLineFragment);

class EntityStixRelationLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Help />
        </ListItemIcon>
        <ListItemText
          primary={
            <div>
              <div className={classes.bodyItem} style={inlineStyles.name}>
                <div className="fakeItem" style={{ width: '80%' }} />
              </div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.entity_type}
              >
                <div className="fakeItem" style={{ width: '70%' }} />
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

EntityStixRelationLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const EntityStixRelationLineDummy = compose(
  inject18n,
  withStyles(styles),
)(EntityStixRelationLineDummyComponent);
