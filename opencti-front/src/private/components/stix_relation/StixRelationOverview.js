import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { compose, includes } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import graphql from 'babel-plugin-relay/macro';
import { createFragmentContainer } from 'react-relay';
import Markdown from 'react-markdown';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import { ArrowRightAlt } from '@material-ui/icons';
import { itemColor } from '../../../utils/Colors';
import { resolveLink } from '../../../utils/Entity';
import inject18n from '../../../components/i18n';
import ItemIcon from '../../../components/ItemIcon';
import ItemConfidenceLevel from '../../../components/ItemConfidenceLevel';
import EntityReports from '../report/EntityReports';

const styles = theme => ({
  container: {
    position: 'relative',
  },
  item: {
    position: 'absolute',
    width: 180,
    height: 80,
    borderRadius: 10,
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
  middle: {
    margin: '0 auto',
    paddingTop: 20,
    width: 200,
    textAlign: 'center',
    color: '#ffffff',
  },
  data: {
    width: '100%',
    margin: '30px 0 30px 0',
  },
  information: {
    float: 'left',
    marginRight: 20,
    width: 300,
  },
  reports: {
    width: 'auto',
    overflow: 'hidden',
  },
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
});

class StixRelationContainer extends Component {
  render() {
    const {
      t, fld, classes, entityId, stixRelation, inversedRelations,
    } = this.props;
    const linkedEntity = stixRelation.to.node;
    const from = linkedEntity.id === entityId ? stixRelation.to.node : stixRelation.from.node;
    const to = linkedEntity.id === entityId ? stixRelation.from.node : stixRelation.to.node;
    const linkTo = resolveLink(to.type);
    const linkFrom = resolveLink(from.type);

    return (
      <div className={classes.container}>
        <Link to={`${linkFrom}/${from.id}`}>
          <div className={classes.item} style={{
            backgroundColor: itemColor(from.type, true),
            top: 10,
            left: 0,
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
        </Link>
        <div className={classes.middle}>
          {includes(to.type, inversedRelations) ? <ArrowRightAlt fontSize='large' style={{ transform: 'rotate(180deg)' }}/> : <ArrowRightAlt fontSize='large'/>}<br/>
          <div style={{
            padding: '5px 8px 5px 8px',
            backgroundColor: '#14262c',
            color: '#ffffff',
            fontSize: 12,
            display: 'inline-block',
          }}>
            {t(`relation_${stixRelation.relationship_type}`)}
          </div>
        </div>
        <Link to={`${linkTo}/${to.id}`}>
          <div className={classes.item} style={{
            backgroundColor: itemColor(to.type, true),
            top: 10,
            right: 0,
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
        </Link>
        <div className='clearfix'/>
        <div className={classes.data}>
          <div className={classes.information}>
            <Typography variant='h4' gutterBottom={true}>
              {t('Information')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <Typography variant='h3' gutterBottom={true}>
                {t('Relationship type')}
              </Typography>
              {t(`relation_${stixRelation.relationship_type}`)}
              <Typography variant='h3' gutterBottom={true} style={{ marginTop: 20 }}>
                {t('First seen')}
              </Typography>
              {fld(stixRelation.first_seen)}
              <Typography variant='h3' gutterBottom={true} style={{ marginTop: 20 }}>
                {t('Last seen')}
              </Typography>
              {fld(stixRelation.last_seen)}
              <Typography variant='h3' gutterBottom={true} style={{ marginTop: 20 }}>
                {t('Confidence level')}
              </Typography>
              <ItemConfidenceLevel level={stixRelation.weight}/>
              <Typography variant='h3' gutterBottom={true} style={{ marginTop: 20 }}>
                {t('Description')}
              </Typography>
              <Markdown className='markdown' source={stixRelation.description}/>
            </Paper>
          </div>
          <div className={classes.reports}>
            <Typography variant='h4' gutterBottom={true}>
              {t('Reports')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <EntityReports entityId={stixRelation.id}/>
            </Paper>
          </div>
        </div>
      </div>
    );
  }
}

StixRelationContainer.propTypes = {
  entityId: PropTypes.string,
  stixRelation: PropTypes.object,
  inversedRelations: PropTypes.array,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
  fld: PropTypes.func,
  history: PropTypes.object,
};

const StixRelationOverview = createFragmentContainer(StixRelationContainer, {
  stixRelation: graphql`
      fragment StixRelationOverview_stixRelation on StixRelation {
          id
          relationship_type
          weight
          first_seen
          last_seen
          description
          from {
              node {
                  id
                  type
                  name
                  description
              }
          }
          to {
              node {
                  id
                  type
                  name
                  description
              }
          }
          reports {
              edges {
                  node {
                      name
                      description
                      published
                  }
              }
          }
      }
  `,
});

export default compose(
  inject18n,
  withStyles(styles),
)(StixRelationOverview);
