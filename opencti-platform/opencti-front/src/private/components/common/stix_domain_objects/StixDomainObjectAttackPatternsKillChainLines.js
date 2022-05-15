import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import Markdown from 'react-markdown';
import * as R from 'ramda';
import withStyles from '@mui/styles/withStyles';
import IconButton from '@mui/material/IconButton';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Collapse from '@mui/material/Collapse';
import { Launch, LockPattern, ProgressWrench } from 'mdi-material-ui';
import { ExpandLess, ExpandMore } from '@mui/icons-material';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import { yearFormat } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import StixCoreRelationshipPopover from '../stix_core_relationships/StixCoreRelationshipPopover';
import ItemYears from '../../../../components/ItemYears';
import ItemMarking from '../../../../components/ItemMarking';

const styles = (theme) => ({
  container: {
    paddingBottom: 70,
  },
  itemIcon: {
    color: theme.palette.primary.main,
  },
  nested: {
    paddingLeft: theme.spacing(4),
  },
  nested2: {
    paddingLeft: theme.spacing(8),
  },
});

class StixDomainObjectAttackPatternsKillChainLines extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedLines: {} };
  }

  handleToggleLine(lineKey) {
    this.setState({
      expandedLines: R.assoc(
        lineKey,
        this.state.expandedLines[lineKey] !== undefined
          ? !this.state.expandedLines[lineKey]
          : false,
        this.state.expandedLines,
      ),
    });
  }

  render() {
    const {
      t,
      classes,
      data,
      entityLink,
      paginationOptions,
      onDelete,
      searchTerm,
      coursesOfAction,
    } = this.props;
    // Extract all kill chain phases
    const filterByKeyword = (n) => searchTerm === ''
      || n.to.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.to.description.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || R.propOr('', 'x_mitre_id', n.to)
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1
      || R.propOr('', 'subattackPatterns_text', n.to)
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1;
    const stixRelationshipsEdges = data.stixCoreRelationships.edges.map((n) => (n.node.to.entity_type === 'Attack-Pattern'
      ? n
      : { node: { ...n.node, to: n.node.from, from: n.node.to } }));
    const killChainPhases = R.pipe(
      // eslint-disable-next-line no-nested-ternary
      R.map((n) => (n.node.killChainPhases.edges.length > 0
        ? n.node.killChainPhases.edges[0].node
        : n.node.to.killChainPhases.edges.length > 0
          ? n.node.to.killChainPhases.edges[0].node
          : { id: 'unknown', phase_name: t('Unknown'), x_opencti_order: 99 })),
      R.uniq,
      R.indexBy(R.prop('id')),
    )(stixRelationshipsEdges);
    const stixCoreRelationships = R.pipe(
      R.map((n) => n.node),
      R.map((n) => R.assoc('startTimeYear', yearFormat(n.start_time), n)),
      R.map((n) => R.assoc('stopTimeYear', yearFormat(n.stop_time), n)),
      R.map((n) => R.assoc(
        'years',
        n.startTimeYear === n.stopTimeYear
          ? n.startTimeYear
          : `${n.startTimeYear} - ${n.stopTimeYear}`,
        n,
      )),
      R.map((n) => R.assoc(
        'killChainPhase',
        // eslint-disable-next-line no-nested-ternary
        n.killChainPhases.edges.length > 0
          ? n.killChainPhases.edges[0].node
          : n.to.killChainPhases.edges.length > 0
            ? n.to.killChainPhases.edges[0].node
            : { id: 'unknown', phase_name: t('Unknown'), x_opencti_order: 99 },
        n,
      )),
      R.map((n) => R.assoc(
        'subattackPatterns_text',
        R.pipe(
          R.map(
            (o) => `${o.node.x_mitre_id} ${o.node.name} ${o.node.description}`,
          ),
          R.join(' | '),
        )(R.pathOr([], ['subAttackPatterns', 'edges'], n.to)),
        n,
      )),
      R.sortWith([R.descend(R.prop('years'))]),
      R.filter(filterByKeyword),
      R.groupBy(R.path(['killChainPhase', 'id'])),
      R.mapObjIndexed((value, key) => R.assoc('attackPatterns', value, killChainPhases[key])),
      R.values,
      R.sortWith([R.ascend(R.prop('x_opencti_order'))]),
    )(stixRelationshipsEdges);
    return (
      <div>
        <div className={classes.container} id="container">
          <List id="test">
            {stixCoreRelationships.map((stixCoreRelationship) => (
              <div key={stixCoreRelationship.id}>
                <ListItem
                  button={true}
                  divider={true}
                  onClick={this.handleToggleLine.bind(
                    this,
                    stixCoreRelationship.id,
                  )}
                >
                  <ListItemIcon>
                    <Launch color="primary" role="img" />
                  </ListItemIcon>
                  <ListItemText primary={stixCoreRelationship.phase_name} />
                  <ListItemSecondaryAction>
                    <IconButton
                      onClick={this.handleToggleLine.bind(
                        this,
                        stixCoreRelationship.id,
                      )}
                      aria-haspopup="true"
                      size="large"
                    >
                      {this.state.expandedLines[stixCoreRelationship.id]
                      === false ? (
                        <ExpandMore />
                        ) : (
                        <ExpandLess />
                        )}
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
                <Collapse
                  in={
                    this.state.expandedLines[stixCoreRelationship.id] !== false
                  }
                >
                  <List>
                    {stixCoreRelationship.attackPatterns.map(
                      (attackPattern) => {
                        const link = `${entityLink}/relations/${attackPattern.id}`;
                        return (
                          <div key={attackPattern.id}>
                            <ListItem
                              classes={{ root: classes.nested }}
                              divider={true}
                              button={true}
                              dense={true}
                              component={coursesOfAction ? 'ul' : Link}
                              to={coursesOfAction ? null : link}
                              onClick={
                                coursesOfAction
                                  ? this.handleToggleLine.bind(
                                    this,
                                    attackPattern.id,
                                  )
                                  : null
                              }
                            >
                              <ListItemIcon>
                                <LockPattern color="primary" role="img" />
                              </ListItemIcon>
                              <ListItemText
                                primary={
                                  <span>
                                    <strong>
                                      {attackPattern.to.x_mitre_id}
                                    </strong>{' '}
                                    - {attackPattern.to.name}
                                  </span>
                                }
                                secondary={
                                  attackPattern.description
                                  && attackPattern.description.length > 0 ? (
                                    <Markdown
                                      remarkPlugins={[remarkGfm, remarkParse]}
                                      parserOptions={{ commonmark: true }}
                                      className="markdown"
                                    >
                                      {attackPattern.description}
                                    </Markdown>
                                    ) : (
                                      t('No description of this usage')
                                    )
                                }
                              />
                              {R.take(
                                1,
                                R.pathOr(
                                  [],
                                  ['markingDefinitions', 'edges'],
                                  attackPattern,
                                ),
                              ).map((markingDefinition) => (
                                <ItemMarking
                                  key={markingDefinition.node.id}
                                  variant="inList"
                                  label={markingDefinition.node.definition}
                                  color={markingDefinition.node.x_opencti_color}
                                />
                              ))}
                              {!coursesOfAction && (
                                <ItemYears
                                  variant="inList"
                                  years={attackPattern.years}
                                />
                              )}
                              <ListItemSecondaryAction>
                                {coursesOfAction ? (
                                  <IconButton
                                    onClick={this.handleToggleLine.bind(
                                      this,
                                      attackPattern.id,
                                    )}
                                    aria-haspopup="true"
                                    size="large"
                                  >
                                    {this.state.expandedLines[
                                      attackPattern.id
                                    ] === false ? (
                                      <ExpandMore />
                                      ) : (
                                      <ExpandLess />
                                      )}
                                  </IconButton>
                                ) : (
                                  <StixCoreRelationshipPopover
                                    stixCoreRelationshipId={attackPattern.id}
                                    paginationOptions={paginationOptions}
                                    onDelete={onDelete}
                                  />
                                )}
                              </ListItemSecondaryAction>
                            </ListItem>
                            {coursesOfAction && (
                              <Collapse
                                in={
                                  this.state.expandedLines[attackPattern.id]
                                  !== false
                                }
                              >
                                <List>
                                  {attackPattern.to.coursesOfAction.edges.map(
                                    (courseOfActionEdge) => {
                                      const courseOfAction = courseOfActionEdge.node;
                                      const courseOfActionLink = `/dashboard/arsenal/courses_of_action/${courseOfAction.id}`;
                                      return (
                                        <ListItem
                                          key={courseOfAction.id}
                                          classes={{ root: classes.nested2 }}
                                          divider={true}
                                          button={true}
                                          dense={true}
                                          component={Link}
                                          to={courseOfActionLink}
                                        >
                                          <ListItemIcon>
                                            <ProgressWrench
                                              color="primary"
                                              role="img"
                                            />
                                          </ListItemIcon>
                                          <ListItemText
                                            primary={courseOfAction.name}
                                            secondary={
                                              courseOfAction.description
                                              && courseOfAction.description
                                                .length > 0 ? (
                                                <Markdown
                                                  remarkPlugins={[
                                                    remarkGfm,
                                                    remarkParse,
                                                  ]}
                                                  parserOptions={{
                                                    commonmark: true,
                                                  }}
                                                  className="markdown"
                                                >
                                                  {courseOfAction.description}
                                                </Markdown>
                                                ) : (
                                                  t(
                                                    'No description of this course of action',
                                                  )
                                                )
                                            }
                                          />
                                        </ListItem>
                                      );
                                    },
                                  )}
                                </List>
                              </Collapse>
                            )}
                          </div>
                        );
                      },
                    )}
                  </List>
                </Collapse>
              </div>
            ))}
          </List>
        </div>
      </div>
    );
  }
}

StixDomainObjectAttackPatternsKillChainLines.propTypes = {
  stixDomainObjectId: PropTypes.string,
  searchTerm: PropTypes.string,
  onDelete: PropTypes.func,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  coursesOfAction: PropTypes.bool,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectAttackPatternsKillChainLines);
