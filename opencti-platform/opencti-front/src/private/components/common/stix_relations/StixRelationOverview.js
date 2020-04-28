import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, withRouter } from 'react-router-dom';
import {
  compose, includes, map, pathOr,
} from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import graphql from 'babel-plugin-relay/macro';
import { DiagramEngine } from 'storm-react-diagrams';
import { createFragmentContainer } from 'react-relay';
import Markdown from 'react-markdown';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Fab from '@material-ui/core/Fab';
import { ArrowRightAlt, Edit } from '@material-ui/icons';
import { itemColor } from '../../../../utils/Colors';
import { resolveLink } from '../../../../utils/Entity';
import { truncate } from '../../../../utils/String';
import inject18n from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import ItemConfidenceLevel from '../../../../components/ItemConfidenceLevel';
import StixRelationEdition, {
  stixRelationEditionDeleteMutation,
} from './StixRelationEdition';
import { commitMutation } from '../../../../relay/environment';
import SimpleLabelFactory from '../../../../components/graph_node/SimpleLabelFactory';
import SimpleLinkFactory from '../../../../components/graph_node/SimpleLinkFactory';
import EntityNodeFactory from '../../../../components/graph_node/EntityNodeFactory';
import GlobalPortFactory from '../../../../components/graph_node/GlobalPortFactory';
import { stixRelationEditionFocus } from './StixRelationEditionOverview';
import ItemMarking from '../../../../components/ItemMarking';
import StixRelationInferences from './StixRelationInferences';
import StixRelationStixRelations from './StixRelationStixRelations';
import EntityLastReports from '../../reports/EntityLastReports';
import ItemAuthor from '../../../../components/ItemAuthor';
import StixObjectNotes from '../stix_object/StixObjectNotes';

const styles = () => ({
  container: {
    position: 'relative',
  },
  editButton: {
    position: 'fixed',
    bottom: 30,
    right: 30,
  },
  editButtonWithPadding: {
    position: 'fixed',
    bottom: 30,
    right: 300,
  },
  item: {
    position: 'absolute',
    width: 180,
    height: 80,
    borderRadius: 10,
  },
  itemHeader: {
    padding: '10px 0 10px 0',
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
    padding: '0 10px 0 10px',
    height: 40,
    maxHeight: 40,
    lineHeight: '40px',
    color: '#ffffff',
    textAlign: 'center',
    wordBreak: 'break-word',
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
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  paperReports: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '25px 15px 15px 15px',
    borderRadius: 6,
  },
});

class StixRelationContainer extends Component {
  constructor(props) {
    super(props);
    const engine = new DiagramEngine();
    engine.installDefaultFactories();
    engine.registerPortFactory(new GlobalPortFactory());
    engine.registerNodeFactory(new EntityNodeFactory());
    engine.registerLinkFactory(new SimpleLinkFactory());
    engine.registerLabelFactory(new SimpleLabelFactory());
    this.state = { openEdit: false, engine };
  }

  handleOpenEdition() {
    this.setState({ openEdit: true });
  }

  handleCloseEdition() {
    const {
      match: {
        params: { relationId },
      },
    } = this.props;
    commitMutation({
      mutation: stixRelationEditionFocus,
      variables: {
        id: relationId,
        input: { focusOn: '' },
      },
    });
    this.setState({ openEdit: false });
  }

  handleDelete() {
    const {
      location,
      match: {
        params: { relationId },
      },
    } = this.props;
    commitMutation({
      mutation: stixRelationEditionDeleteMutation,
      variables: {
        id: relationId,
      },
      onCompleted: () => {
        this.handleCloseEdition();
        this.props.history.push(
          location.pathname.replace(`/relations/${relationId}`, ''),
        );
      },
    });
  }

  render() {
    const {
      t, fld, classes, stixRelation, paddingRight,
    } = this.props;
    const { from } = stixRelation;
    const { to } = stixRelation;
    const linkFrom = from.entity_type === 'stix-relation'
      || from.entity_type === 'stix_relation'
      ? `${resolveLink(from.from.entity_type)}/${
        from.from.id
      }/knowledge/relations`
      : resolveLink(from.entity_type);
    const linkTo = to.entity_type === 'stix-relation' || to.entity_type === 'stix_relation'
      ? `${resolveLink(to.from.entity_type)}/${
        to.from.id
      }/knowledge/relations`
      : resolveLink(to.entity_type);
    return (
      <div className={classes.container}>
        <Link to={`${linkFrom}/${from.id}`}>
          <div
            className={classes.item}
            style={{
              border: `2px solid ${itemColor(from.entity_type)}`,
              top: 10,
              left: 0,
            }}
          >
            <div
              className={classes.itemHeader}
              style={{
                borderBottom: `1px solid ${itemColor(from.entity_type)}`,
              }}
            >
              <div className={classes.icon}>
                <ItemIcon
                  type={from.entity_type}
                  color={itemColor(from.entity_type)}
                  size="small"
                />
              </div>
              <div className={classes.type}>
                {includes('Stix-Observable', from.parent_types)
                  ? t(`observable_${from.entity_type}`)
                  : t(
                    `entity_${
                      from.entity_type === 'stix_relation'
                        || from.entity_type === 'stix-relation'
                        ? from.parent_types[0]
                        : from.entity_type
                    }`,
                  )}
              </div>
            </div>
            <div className={classes.content}>
              <span className={classes.name}>
                {truncate(
                  /* eslint-disable-next-line no-nested-ternary */
                  includes('Stix-Observable', from.parent_types)
                    ? from.observable_value
                    : from.entity_type === 'stix_relation'
                      || from.entity_type === 'stix-relation'
                      ? `${from.from.name} ${String.fromCharCode(8594)} ${
                        from.to.name
                      }`
                      : from.name,
                  50,
                )}
              </span>
            </div>
          </div>
        </Link>
        <div className={classes.middle}>
          <ArrowRightAlt fontSize="large" />
          <br />
          <div
            style={{
              padding: '5px 8px 5px 8px',
              backgroundColor: '#14262c',
              color: '#ffffff',
              fontSize: 12,
              display: 'inline-block',
            }}
          >
            <strong>{t(`relation_${stixRelation.relationship_type}`)}</strong>
            {stixRelation.relationship_type === 'indicates'
            && !stixRelation.inferred ? (
              <span>
                <br />{' '}
                {stixRelation.role_played
                  ? t(stixRelation.role_played)
                  : t('Unknown')}
              </span>
              ) : (
                ''
              )}
          </div>
        </div>
        <Link to={`${linkTo}/${to.id}`}>
          <div
            className={classes.item}
            style={{
              border: `2px solid ${itemColor(to.entity_type)}`,
              top: 10,
              right: 0,
            }}
          >
            <div
              className={classes.itemHeader}
              style={{
                borderBottom: `1px solid ${itemColor(to.entity_type)}`,
              }}
            >
              <div className={classes.icon}>
                <ItemIcon
                  type={to.entity_type}
                  color={itemColor(to.entity_type)}
                  size="small"
                />
              </div>
              <div className={classes.type}>
                {includes('Stix-Observable', to.parent_types)
                  ? t(`observable_${to.entity_type}`)
                  : t(
                    `entity_${
                      to.entity_type === 'stix_relation'
                        || to.entity_type === 'stix-relation'
                        ? to.parent_types[0]
                        : to.entity_type
                    }`,
                  )}
              </div>
            </div>
            <div className={classes.content}>
              <span className={classes.name}>
                {truncate(
                  /* eslint-disable-next-line no-nested-ternary */
                  includes('Stix-Observable', to.parent_types)
                    ? to.observable_value
                    : to.entity_type === 'stix_relation'
                      || to.entity_type === 'stix-relation'
                      ? `${to.from.name} ${String.fromCharCode(8594)} ${
                        to.to.name
                      }`
                      : to.name,
                  50,
                )}
              </span>
            </div>
          </div>
        </Link>
        <div className="clearfix" style={{ height: 20 }} />
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Information')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Marking')}
              </Typography>
              {stixRelation.markingDefinitions.edges.length > 0 ? (
                map(
                  (markingDefinition) => (
                    <ItemMarking
                      key={markingDefinition.node.id}
                      label={markingDefinition.node.definition}
                    />
                  ),
                  stixRelation.markingDefinitions.edges,
                )
              ) : (
                <ItemMarking label="TLP:WHITE" />
              )}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Creation date')}
              </Typography>
              {stixRelation.inferred ? '-' : fld(stixRelation.created_at)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Modification date')}
              </Typography>
              {stixRelation.inferred ? '-' : fld(stixRelation.updated_at)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Author')}
              </Typography>
              <ItemAuthor
                createdByRef={pathOr(
                  null,
                  ['createdByRef', 'node'],
                  stixRelation,
                )}
              />
            </Paper>
          </Grid>
          <Grid item={true} xs={6}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Details')}
            </Typography>
            <Paper classes={{ root: classes.paper }} elevation={2}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Confidence level')}
              </Typography>
              <ItemConfidenceLevel
                level={stixRelation.inferred ? 99 : stixRelation.weight}
              />
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('First seen')}
              </Typography>
              {stixRelation.inferred ? '-' : fld(stixRelation.first_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Last seen')}
              </Typography>
              {stixRelation.inferred ? '-' : fld(stixRelation.last_seen)}
              <Typography
                variant="h3"
                gutterBottom={true}
                style={{ marginTop: 20 }}
              >
                {t('Description')}
              </Typography>
              <Markdown
                className="markdown"
                source={stixRelation.description}
              />
            </Paper>
          </Grid>
        </Grid>
        <div>
          {stixRelation.inferred ? (
            <div style={{ margin: '50px 0 60px 0' }}>
              <Typography variant="h4" gutterBottom={true}>
                {t('Inference explanation')}
              </Typography>
              <Paper
                classes={{ root: classes.paper }}
                elevation={2}
                style={{ height: 400 }}
              >
                <StixRelationInferences
                  engine={this.state.engine}
                  stixRelation={stixRelation}
                  from={from}
                  to={to}
                />
              </Paper>
            </div>
          ) : (
            <div style={{ margin: '40px 0 0px 0' }}>
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={6}>
                  <StixRelationStixRelations entityId={stixRelation.id} />
                </Grid>
                <Grid item={true} xs={6}>
                  <EntityLastReports entityId={stixRelation.id} />
                </Grid>
              </Grid>
              <StixObjectNotes
                marginTop={55}
                entityId={stixRelation.id}
                inputType="relationRefs"
              />
            </div>
          )}
        </div>
        {stixRelation.inferred ? (
          ''
        ) : (
          <div>
            <Fab
              onClick={this.handleOpenEdition.bind(this)}
              color="secondary"
              aria-label="Edit"
              className={
                paddingRight
                  ? classes.editButtonWithPadding
                  : classes.editButton
              }
            >
              <Edit />
            </Fab>
            <StixRelationEdition
              open={this.state.openEdit}
              stixRelationId={stixRelation.id}
              handleClose={this.handleCloseEdition.bind(this)}
              handleDelete={this.handleDelete.bind(this)}
            />
          </div>
        )}
      </div>
    );
  }
}

StixRelationContainer.propTypes = {
  entityId: PropTypes.string,
  stixRelation: PropTypes.object,
  paddingRight: PropTypes.bool,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
  fld: PropTypes.func,
  match: PropTypes.object,
  history: PropTypes.object,
  location: PropTypes.object,
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
      inferred
      role_played
      fromRole
      toRole
      created_at
      updated_at
      createdByRef {
        node {
          id
          name
          entity_type
        }
      }
      markingDefinitions {
        edges {
          node {
            id
            definition
          }
        }
      }
      inferences {
        edges {
          node {
            id
            relationship_type
            role_played
            inferred
            from {
              id
              name
              entity_type
              parent_types
              ... on StixObservable {
                observable_value
              }
            }
            to {
              id
              name
              entity_type
              parent_types
              ... on StixObservable {
                observable_value
              }
              ... on StixRelation {
                from {
                  id
                  entity_type
                  name
                }
                to {
                  id
                  entity_type
                  name
                }
              }
            }
          }
        }
      }
      from {
        id
        entity_type
        parent_types
        name
        description
        ... on StixObservable {
          observable_value
        }
        ... on StixRelation {
          from {
            id
            entity_type
            name
          }
          to {
            id
            entity_type
            name
          }
        }
      }
      to {
        id
        entity_type
        parent_types
        name
        description
        ... on StixObservable {
          observable_value
        }
        ... on StixRelation {
          from {
            id
            entity_type
            name
          }
          to {
            id
            entity_type
            name
          }
        }
      }
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(StixRelationOverview);
