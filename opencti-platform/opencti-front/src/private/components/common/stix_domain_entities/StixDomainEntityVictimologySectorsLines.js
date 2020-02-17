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
  take,
  filter,
  pathOr,
  assocPath,
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
import { FileImageOutline } from 'mdi-material-ui';
import { Domain, ExpandLess, ExpandMore } from '@material-ui/icons';
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
import ItemIcon from '../../../../components/ItemIcon';

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

class StixDomainEntityVictimologySectorsLinesComponent extends Component {
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
        fileDownload(blob, 'Victimology.png', 'image/png');
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

    // Sectors
    const sectorsRelations = pipe(
      map((n) => n.node),
      filter((n) => n.to.entity_type === 'sector'),
      map((n) => assocPath(
        ['to', 'parentSectors'],
        map((o) => o.node, n.to.parentSectors.edges),
        n,
      )),
    )(data.stixRelations.edges);

    // Add parent sectors


    console.log(sectorsRelations);
    // Insert organizations in sector

    const stixRelations = [];
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
                    <Domain color="primary" role="img" />
                  </ListItemIcon>
                  <ListItemText primary={stixRelation.name} />
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
                    {stixRelation.victims.map((victim) => {
                      const link = `${entityLink}/relations/${victim.id}`;
                      return (
                        <ListItem
                          key={victim.id}
                          classes={{ root: classes.nested }}
                          divider={true}
                          button={true}
                          dense={true}
                          component={Link}
                          to={link}
                        >
                          <ListItemIcon className={classes.itemIcon}>
                            <ItemIcon type={victim.to.entity_type} />
                          </ListItemIcon>
                          <ListItemText
                            primary={victim.to.name}
                            secondary={
                              // eslint-disable-next-line no-nested-ternary
                              victim.description
                              && victim.description.length > 0 ? (
                                <Markdown
                                  className="markdown"
                                  source={victim.description}
                                />
                                ) : victim.inferred ? (
                                <i>{t('This relation is inferred')}</i>
                                ) : (
                                  t('No description of this usage')
                                )
                            }
                          />
                          {take(
                            1,
                            pathOr([], ['markingDefinitions', 'edges'], victim),
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
                              victim.inferred ? t('Inferred') : victim.years
                            }
                            disabled={victim.inferred}
                          />
                          <ListItemSecondaryAction>
                            <StixRelationPopover
                              stixRelationId={victim.id}
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
            targetEntityTypes={['Identity']}
            paginationOptions={paginationOptions}
          />
        </Security>
      </div>
    );
  }
}

StixDomainEntityVictimologySectorsLinesComponent.propTypes = {
  stixDomainEntityId: PropTypes.string,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export const stixDomainEntityVictimologySectorsLinesStixRelationsQuery = graphql`
  query StixDomainEntityVictimologySectorsLinesStixRelationsQuery(
    $fromId: String
    $toTypes: [String]
    $relationType: String
    $inferred: Boolean
    $first: Int
  ) {
    ...StixDomainEntityVictimologySectorsLines_data
  }
`;

const StixDomainEntityVictimologySectorsSectorLines = createRefetchContainer(
  StixDomainEntityVictimologySectorsLinesComponent,
  {
    data: graphql`
      fragment StixDomainEntityVictimologySectorsLines_data on Query {
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
                entity_type
                ... on Organization {
                  sectors {
                    edges {
                      node {
                        id
                        name
                      }
                    }
                  }
                }
                ... on Sector {
                  parentSectors {
                    edges {
                      node {
                        id
                        name
                      }
                    }
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
  stixDomainEntityVictimologySectorsLinesStixRelationsQuery,
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityVictimologySectorsSectorLines);
