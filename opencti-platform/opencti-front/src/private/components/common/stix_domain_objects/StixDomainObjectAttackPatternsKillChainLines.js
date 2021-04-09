import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import Markdown from 'react-markdown';
import * as R from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import IconButton from '@material-ui/core/IconButton';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemText from '@material-ui/core/ListItemText';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemSecondaryAction from '@material-ui/core/ListItemSecondaryAction';
import Collapse from '@material-ui/core/Collapse';
import { Launch, LockPattern } from 'mdi-material-ui';
import { ExpandLess, ExpandMore } from '@material-ui/icons';
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
    } = this.props;
    // Extract all kill chain phases
    const filterByKeyword = (n) => searchTerm === ''
      || n.to.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.to.description.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.to.x_mitre_id.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || R.propOr('', 'subattackPatterns_text', n)
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1;
    const killChainPhases = R.pipe(
      // eslint-disable-next-line no-nested-ternary
      R.map((n) => (n.node.killChainPhases.edges.length > 0
        ? n.node.killChainPhases.edges[0].node
        : n.node.to.killChainPhases.edges.length > 0
          ? n.node.to.killChainPhases.edges[0].node
          : { id: 'unknown', phase_name: t('Unknown'), x_opencti_order: 99 })),
      R.uniq,
      R.indexBy(R.prop('id')),
    )(data.stixCoreRelationships.edges);
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
    )(data.stixCoreRelationships.edges);
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
                                  <strong>{attackPattern.to.x_mitre_id}</strong>{' '}
                                  - {attackPattern.to.name}
                                </span>
                              }
                              secondary={
                                attackPattern.description
                                && attackPattern.description.length > 0 ? (
                                  <Markdown
                                    className="markdown"
                                    source={attackPattern.description}
                                  />
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
                            <ItemYears
                              variant="inList"
                              years={attackPattern.years}
                            />
                            <ListItemSecondaryAction>
                              <StixCoreRelationshipPopover
                                stixCoreRelationshipId={attackPattern.id}
                                paginationOptions={paginationOptions}
                                onDelete={onDelete}
                              />
                            </ListItemSecondaryAction>
                          </ListItem>
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
  handleDelete: PropTypes.func,
  data: PropTypes.object,
  entityLink: PropTypes.string,
  paginationOptions: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default R.compose(
  inject18n,
  withStyles(styles),
)(StixDomainObjectAttackPatternsKillChainLines);
