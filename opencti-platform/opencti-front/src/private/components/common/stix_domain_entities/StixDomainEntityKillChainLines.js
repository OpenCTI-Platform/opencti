import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import html2canvas from 'html2canvas';
import fileDownload from 'js-file-download';
import Markdown from 'react-markdown';
import {
  compose,
  pipe,
  map,
  assoc,
  groupBy,
  path,
  mapObjIndexed,
  uniq,
  indexBy,
  prop,
  values,
  sortWith,
  ascend,
  descend,
  take,
  pathOr,
} from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import IconButton from '@material-ui/core/IconButton';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Collapse from '@material-ui/core/Collapse';
import { Launch, LockPattern, FileImageOutline } from 'mdi-material-ui';
import { ExpandLess, ExpandMore } from '@material-ui/icons';
import { createRefetchContainer } from 'react-relay';
import Tooltip from '@material-ui/core/Tooltip';
import { yearFormat } from '../../../../utils/Time';
import inject18n from '../../../../components/i18n';
import StixRelationPopover from '../stix_relations/StixRelationPopover';
import StixRelationCreationFromEntity from '../stix_relations/StixRelationCreationFromEntity';
import ItemYears from '../../../../components/ItemYears';
import SearchInput from '../../../../components/SearchInput';
import Security, { KNOWLEDGE_KNUPDATE } from '../../../../utils/Security';
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
});

class StixDomainEntityKillChainLinesComponent extends Component {
  constructor(props) {
    super(props);
    this.state = { expandedLines: {}, searchTerm: '' };
  }

  handleSearch(value) {
    this.setState({ searchTerm: value });
  }

  handleToggleLine(lineKey) {
    this.setState({
      expandedLines: assoc(
        lineKey,
        this.state.expandedLines[lineKey] !== undefined
          ? !this.state.expandedLines[lineKey]
          : false,
        this.state.expandedLines,
      ),
    });
  }

  setInlineStyles(targetElem) {
    const transformProperties = [
      'fill',
      'color',
      'font-size',
      'stroke',
      'font',
    ];
    const svgElems = Array.from(targetElem.getElementsByTagName('svg'));
    function recurseElementChildren(node) {
      if (!node.style) return;
      const inlineStyles = getComputedStyle(node);
      for (const transformProperty of transformProperties) {
        node.style[transformProperty] = inlineStyles[transformProperty];
      }
      for (const child of Array.from(node.childNodes)) {
        recurseElementChildren(child);
      }
    }
    for (const svgElement of svgElems) {
      if (svgElement.getAttribute('role') === 'img') {
        recurseElementChildren(svgElement);
        svgElement.setAttribute(
          'width',
          svgElement.getBoundingClientRect().width,
        );
        svgElement.setAttribute(
          'height',
          svgElement.getBoundingClientRect().height,
        );
      }
    }
  }

  exportImage() {
    const container = document.getElementById('container');
    this.setInlineStyles(container);
    html2canvas(container, {
      useCORS: true,
      allowTaint: true,
      backgroundColor: '#303030',
    }).then((canvas) => {
      canvas.toBlob((blob) => {
        fileDownload(blob, 'KillChain.png', 'image/png');
      });
    });
  }

  render() {
    const {
      t,
      classes,
      data,
      entityLink,
      paginationOptions,
      stixDomainEntityId,
    } = this.props;
    // Extract all kill chain phases
    const killChainPhases = pipe(
      // eslint-disable-next-line no-nested-ternary
      map((n) => (n.node.killChainPhases.edges.length > 0
        ? n.node.killChainPhases.edges[0].node
        : n.node.to.killChainPhases.edges.length > 0
          ? n.node.to.killChainPhases.edges[0].node
          : { id: 'unknown', phase_name: t('Unknown'), phase_order: 99 })),
      uniq,
      indexBy(prop('id')),
    )(data.stixRelations.edges);
    const stixRelations = pipe(
      map((n) => n.node),
      map((n) => assoc('firstSeenYear', yearFormat(n.first_seen), n)),
      map((n) => assoc('lastSeenYear', yearFormat(n.last_seen), n)),
      map((n) => assoc(
        'years',
        n.firstSeenYear === n.lastSeenYear
          ? n.firstSeenYear
          : `${n.firstSeenYear} - ${n.lastSeenYear}`,
        n,
      )),
      map((n) => assoc(
        'killChainPhase',
        // eslint-disable-next-line no-nested-ternary
        n.killChainPhases.edges.length > 0
          ? n.killChainPhases.edges[0].node
          : n.to.killChainPhases.edges.length > 0
            ? n.to.killChainPhases.edges[0].node
            : { id: 'unknown', phase_name: t('Unknown'), phase_order: 99 },
        n,
      )),
      sortWith([descend(prop('years'))]),
      groupBy(path(['killChainPhase', 'id'])),
      mapObjIndexed((value, key) => assoc('attackPatterns', value, killChainPhases[key])),
      values,
      sortWith([ascend(prop('phase_order'))]),
    )(data.stixRelations.edges);
    return (
      <div>
        <div style={{ float: 'left' }}>
          <SearchInput
            variant="small"
            onSubmit={this.handleSearch.bind(this)}
          />
        </div>
        <div style={{ float: 'right', paddingRight: 18 }}>
          <Tooltip title={t('Export as image')}>
            <IconButton color="primary" onClick={this.exportImage.bind(this)}>
              <FileImageOutline />
            </IconButton>
          </Tooltip>
        </div>
        <div className="clearfix" />
        <div className={classes.container} id="container">
          <List id="test">
            {stixRelations.map((stixRelation) => (
              <div key={stixRelation.id}>
                <ListItem
                  button={true}
                  divider={true}
                  onClick={this.handleToggleLine.bind(this, stixRelation.id)}
                >
                  <ListItemIcon>
                    <Launch color="primary" role="img" />
                  </ListItemIcon>
                  <ListItemText primary={stixRelation.phase_name} />
                  <ListItemSecondaryAction>
                    <IconButton
                      onClick={this.handleToggleLine.bind(
                        this,
                        stixRelation.id,
                      )}
                      aria-haspopup="true"
                    >
                      {this.state.expandedLines[stixRelation.id] === false ? (
                        <ExpandMore />
                      ) : (
                        <ExpandLess />
                      )}
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
                <Collapse
                  in={this.state.expandedLines[stixRelation.id] !== false}
                >
                  <List>
                    {stixRelation.attackPatterns.map((attackPattern) => {
                      const link = `${entityLink}/relations/${attackPattern.id}`;
                      return (
                        <ListItem
                          key={attackPattern.id}
                          classes={{ root: classes.nested }}
                          divider={true}
                          button={true}
                          dense={true}
                          component={Link}
                          to={link}
                        >
                          <ListItemIcon>
                            <LockPattern color="primary" role="img" />
                          </ListItemIcon>
                          <ListItemText
                            primary={
                              <span>
                                <strong>{attackPattern.to.external_id}</strong>{' '}
                                - {attackPattern.to.name}
                              </span>
                            }
                            secondary={
                              // eslint-disable-next-line no-nested-ternary
                              attackPattern.description
                              && attackPattern.description.length > 0 ? (
                                <Markdown
                                  className="markdown"
                                  source={attackPattern.description}
                                />
                                ) : attackPattern.inferred ? (
                                <i>{t('This relation is inferred')}</i>
                                ) : (
                                  t('No description of this usage')
                                )
                            }
                          />
                          {take(
                            1,
                            pathOr(
                              [],
                              ['markingDefinitions', 'edges'],
                              attackPattern,
                            ),
                          ).map((markingDefinition) => (
                            <ItemMarking
                              key={markingDefinition.node.id}
                              variant="inList"
                              label={markingDefinition.node.definition}
                              color={markingDefinition.node.color}
                            />
                          ))}
                          <ItemYears
                            variant="inList"
                            years={
                              attackPattern.inferred
                                ? t('Inferred')
                                : attackPattern.years
                            }
                            disabled={attackPattern.inferred}
                          />
                          <ListItemSecondaryAction>
                            <StixRelationPopover
                              stixRelationId={attackPattern.id}
                              paginationOptions={paginationOptions}
                              onDelete={this.props.relay.refetch.bind(this)}
                            />
                          </ListItemSecondaryAction>
                        </ListItem>
                      );
                    })}
                  </List>
                </Collapse>
              </div>
            ))}
          </List>
        </div>
        <Security needs={[KNOWLEDGE_KNUPDATE]}>
          <StixRelationCreationFromEntity
            entityId={stixDomainEntityId}
            isFrom={true}
            paddingRight={true}
            onCreate={this.props.relay.refetch.bind(this)}
            targetEntityTypes={['Attack-Pattern']}
            paginationOptions={paginationOptions}
          />
        </Security>
      </div>
    );
  }
}

StixDomainEntityKillChainLinesComponent.propTypes = {
  stixDomainEntityId: PropTypes.string,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixDomainEntityKillChainLinesStixRelationsQuery = graphql`
  query StixDomainEntityKillChainLinesStixRelationsQuery(
    $fromId: String
    $toTypes: [String]
    $relationType: String
    $inferred: Boolean
    $first: Int
  ) {
    ...StixDomainEntityKillChainLines_data
  }
`;

const StixDomainEntityKillChainLines = createRefetchContainer(
  StixDomainEntityKillChainLinesComponent,
  {
    data: graphql`
      fragment StixDomainEntityKillChainLines_data on Query {
        stixRelations(
          fromId: $fromId
          toTypes: $toTypes
          relationType: $relationType
          inferred: $inferred
          first: $first
        ) {
          edges {
            node {
              id
              description
              first_seen
              last_seen
              inferred
              to {
                id
                name
                ... on AttackPattern {
                  external_id
                  killChainPhases {
                    edges {
                      node {
                        id
                        phase_name
                        phase_order
                      }
                    }
                  }
                }
              }
              killChainPhases {
                edges {
                  node {
                    id
                    phase_name
                    phase_order
                  }
                }
              }
              markingDefinitions {
                edges {
                  node {
                    id
                    definition
                    color
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  stixDomainEntityKillChainLinesStixRelationsQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityKillChainLines);
