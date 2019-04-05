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
import { Tag } from 'mdi-material-ui';
import { compose, pathOr, take } from 'ramda';
import inject18n from '../../../components/i18n';
import ItemMarking from '../../../components/ItemMarking';

const styles = theme => ({
  item: {
    paddingLeft: 10,
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
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
  entity_type: {
    float: 'left',
    width: '20%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  observable_value: {
    float: 'left',
    width: '40%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  created_at: {
    float: 'left',
    width: '15%',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  marking: {
    float: 'left',
    height: 20,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

class StixObservableLineComponent extends Component {
  render() {
    const {
      t, fd, classes, stixObservable,
    } = this.props;

    return (
      <ListItem
        classes={{ root: classes.item }}
        divider={true}
        component={Link}
        to={`/dashboard/observables/all/${stixObservable.id}`}
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
                {t(`observable_${stixObservable.entity_type}`)}
              </div>
              <div
                className={classes.bodyItem}
                style={inlineStyles.observable_value}
              >
                {stixObservable.observable_value}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created_at}>
                {fd(stixObservable.created_at)}
              </div>
              <div className={classes.bodyItem} style={inlineStyles.marking}>
                {take(
                  1,
                  pathOr([], ['markingDefinitions', 'edges'], stixObservable),
                ).map(markingDefinition => (
                  <ItemMarking
                    key={markingDefinition.node.id}
                    variant="inList"
                    label={markingDefinition.node.definition}
                  />
                ))}
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

StixObservableLineComponent.propTypes = {
  stixObservable: PropTypes.object,
  classes: PropTypes.object,
  fd: PropTypes.func,
  t: PropTypes.func,
};

const StixObservableLineFragment = createFragmentContainer(
  StixObservableLineComponent,
  {
    stixObservable: graphql`
      fragment StixObservableLine_stixObservable on StixObservable {
        id
        entity_type
        observable_value
        created_at
        markingDefinitions {
          edges {
            node {
              id
              definition
            }
          }
        }
      }
    `,
  },
);

export const StixObservableLine = compose(
  inject18n,
  withStyles(styles),
)(StixObservableLineFragment);

class StixObservableLineDummyComponent extends Component {
  render() {
    const { classes } = this.props;
    return (
      <ListItem classes={{ default: classes.item }} divider={true}>
        <ListItemIcon classes={{ root: classes.itemIconDisabled }}>
          <Tag />
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
              <div
                className={classes.bodyItem}
                style={inlineStyles.observable_value}
              >
                <div className="fakeItem" style={{ width: '70%' }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.created_at}>
                <div className="fakeItem" style={{ width: 140 }} />
              </div>
              <div className={classes.bodyItem} style={inlineStyles.marking}>
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

StixObservableLineDummyComponent.propTypes = {
  classes: PropTypes.object,
};

export const StixObservableLineDummy = compose(
  inject18n,
  withStyles(styles),
)(StixObservableLineDummyComponent);
