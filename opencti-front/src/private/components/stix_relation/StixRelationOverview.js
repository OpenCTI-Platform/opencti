import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import { itemColor } from '../../../utils/Colors';
import inject18n from '../../../components/i18n';
import graphql from "babel-plugin-relay/macro";
import { createFragmentContainer } from "react-relay";

const styles = () => ({
  item: {
    position: 'absolute',
    width: 180,
    height: 80,
  },
  itemHeader: {
    padding: '10px 0 10px 0',
    borderBottom: '1px solid #ffffff',
  },
  icon: {
    position: 'absolute',
    top: 8,
    left: 5,
    fontSize: 8,
  },
  type: {
    width: '100%',
    textAlign: 'center',
    color: '#ffffff',
    fontSize: 11,
  },
  content: {
    width: '100%',
    height: 40,
    maxHeight: 40,
    lineHeight: '40px',
    color: '#ffffff',
    textAlign: 'center',
  },
  name: {
    display: 'inline-block',
    lineHeight: 1,
    fontSize: 12,
    verticalAlign: 'middle',
  },
  relation: {
    position: 'relative',
    height: 100,
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
    padding: 10,
    marginBottom: 10,
  },
  relationCreation: {
    position: 'relative',
    height: 100,
    transition: 'background-color 0.1s ease',
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
    padding: 10,
  },
  relationCreate: {
    position: 'relative',
    height: 100,
  },
  middle: {
    margin: '0 auto',
    width: 200,
    textAlign: 'center',
    padding: 0,
    color: '#ffffff',
  },
});

class StixRelationContainer extends Component {
  render() {
    const { classes, relationId } = this.props;
    return (
      <div>
        <div className={classes.item} style={{
          backgroundColor: itemColor(from.type, true),
          top: 10,
          left: 10,
        }}>
          <div className={classes.itemHeader}>
            <div className={classes.icon}>
              <ItemIcon type={from.type} color={itemColor(from.type, false)} size='small'/>
            </div>
            <div className={classes.type}>
              {t(`entity_${from.type}`)}
            </div>
          </div>
          <div className={classes.content}>
            <span className={classes.name}>{from.name}</span>
          </div>
        </div>
        <div className={classes.middle} style={{ paddingTop: 25 }}>
          <ArrowRightAlt fontSize='large'/>
        </div>
        <div className={classes.item} style={{
          backgroundColor: itemColor(to.type, true),
          top: 10,
          right: 10,
        }}>
          <div className={classes.itemHeader}>
            <div className={classes.icon}>
              <ItemIcon type={to.type} color={itemColor(to.type, false)} size='small'/>
            </div>
            <div className={classes.type}>
              {t(`entity_${to.type}`)}
            </div>
          </div>
          <div className={classes.content}>
            <span className={classes.name}>{to.name}</span>
          </div>
        </div>
      </div>
    );
  }
}

StixRelationContainer.propTypes = {
  stixRelation: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

const StixRelationOverview = createFragmentContainer(StixRelationContainer, {
  stixRelation: graphql`
      fragment StixRelationEditionOverview_stixRelation on StixRelationEdge {
          node {
              id
              weight
              first_seen
              last_seen
              description
              report {
                  edges {
                      node {
                          name
                          description
                          published
                      }
                  }
              }
          }
          from {
              id
              type
              name
              description
          }
          to {
              id
              type
              name
              description
          }
      }
  `
});

export default compose(
  inject18n,
  withStyles(styles),
)(StixRelationOverview);
