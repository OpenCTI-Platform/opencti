import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { createRefetchContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core';
import inject18n from '../../../../components/i18n';
import { attackPatternsLinesQuery } from './AttackPatternsLines';
import { computeLevel } from '../../../../utils/Number';
import AttackPtternsMatrixBar from './AttackPtternsMatrixBar';
import { truncate } from '../../../../utils/String';

const styles = (theme) => ({
  container: {
    margin: '15px 0 -24px 0',
    overflow: 'scroll',
    whiteSpace: 'nowrap',
    paddingBottom: 20,
    minWidth: 'calc(100vw - 243px)',
    minHeight: 'calc(100vh - 205px)',
    width: 'calc(100vw - 243px)',
    height: 'calc(100vh - 205px)',
    maxWidth: 'calc(100vw - 243px)',
    maxHeight: 'calc(100vh - 205px)',
  },
  containerWithMarginRight: {
    margin: '15px 0 -24px 0',
    overflow: 'scroll',
    whiteSpace: 'nowrap',
    paddingBottom: 20,
    minWidth: 'calc(100vw - 430px)',
    minHeight: 'calc(100vh - 235px)',
    width: 'calc(100vw - 430px)',
    height: 'calc(100vh - 235px)',
    maxWidth: 'calc(100vw - 430px)',
    maxHeight: 'calc(100vh - 235px)',
  },
  header: {
    borderBottom: theme.palette.divider,
    marginBottom: 10,
  },
  headerElement: {
    display: 'inline-block',
    textAlign: 'center',
    width: 150,
    verticalAlign: 'top',
    margin: '0 5px 0 5px',
  },
  title: {
    margin: '0 auto',
    textAlign: 'center',
    fontSize: 15,
    fontWeight: 600,
  },
  subtitle: {
    fontSize: 11,
  },
  column: {
    display: 'inline-block',
    width: 150,
    verticalAlign: 'top',
    margin: '0 5px 0 5px',
  },
  element: {
    padding: 10,
    width: '100%',
    whiteSpace: 'normal',
    backgroundColor: theme.palette.background.paper,
    verticalAlign: 'top',
  },
  name: {
    fontSize: 10,
    fontWeight: 400,
  },
});

const colors = [
  ['#265058', 'transparent'],
  ['#fff59d', 'rgba(255,245,157,0.2)'],
  ['#ffe082', 'rgba(255,224,130,0.2)'],
  ['#ffb300', 'rgba(255,179,0,0.2)'],
  ['#ffb74d', 'rgba(255,183,77,0.2)'],
  ['#fb8c00', 'rgba(251,140,0,0.2)'],
  ['#d95f00', 'rgba(217,95,0,0.2)'],
  ['#e64a19', 'rgba(230,74,25,0.2)'],
  ['#f44336', 'rgba(244,67,54,0.2)'],
  ['#d32f2f', 'rgba(211,47,47,0.2)'],
  ['#b71c1c', 'rgba(183,28,28,0.2)'],
];

class AttackPatternsMatrixColumnsComponent extends Component {
  constructor(props) {
    super(props);
    this.state = {
      currentModeOnlyActive: false,
      currentKillChain: 'mitre-attack',
    };
  }

  handleToggleModeOnlyActive() {
    this.setState({ currentModeOnlyActive: !this.state.currentModeOnlyActive });
  }

  handleChangeKillChain(event) {
    const { value } = event.target;
    this.setState({ currentKillChain: value });
  }

  level(attackPattern, maxNumberOfSameAttackPattern) {
    const { attackPatterns } = this.props;
    const numberOfCorrespondingAttackPatterns = R.filter(
      (n) => n.id === attackPattern.id
        || (attackPattern.subAttackPatternsIds
          && R.includes(n.id, attackPattern.subAttackPatternsIds)),
      attackPatterns,
    ).length;
    return computeLevel(
      numberOfCorrespondingAttackPatterns,
      0,
      maxNumberOfSameAttackPattern,
      0,
      10,
    );
  }

  render() {
    const {
      t,
      data,
      classes,
      attackPatterns: selectedPatterns,
      marginRight,
      searchTerm,
    } = this.props;
    const { currentModeOnlyActive, currentKillChain } = this.state;
    const sortByOrder = R.sortBy(R.prop('x_opencti_order'));
    const sortByName = R.sortBy(R.prop('name'));
    const filterByKeyword = (n) => searchTerm === ''
      || n.name.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.description.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || n.x_mitre_id.toLowerCase().indexOf(searchTerm.toLowerCase()) !== -1
      || R.propOr('', 'subattackPatterns_text', n)
        .toLowerCase()
        .indexOf(searchTerm.toLowerCase()) !== -1;
    const maxNumberOfSameAttackPattern = Math.max(
      ...R.pipe(
        R.map((n) => [
          n,
          ...R.map((o) => o.node, n.parentAttackPatterns.edges),
        ]),
        R.flatten,
        R.countBy(R.prop('id')),
        R.values,
      )(selectedPatterns),
    );
    const filterSubattackPattern = (n) => n.isSubAttackPattern === false;
    const attackPatterns = R.pipe(
      R.map((n) => ({
        ...n.node,
        subAttackPatternsIds: R.map(
          (o) => o.node.id,
          n.node.subAttackPatterns.edges,
        ),
      })),
      R.map((n) => ({
        ...n,
        level: this.level(n, maxNumberOfSameAttackPattern),
        subattackPatterns_text: R.pipe(
          R.map(
            (o) => `${o.node.x_mitre_id} ${o.node.name} ${o.node.description}`,
          ),
          R.join(' | '),
        )(R.pathOr([], ['subAttackPatterns', 'edges'], n)),
        subAttackPatterns: R.pipe(
          R.map((o) => R.assoc(
            'level',
            this.level(o.node, maxNumberOfSameAttackPattern),
            o.node,
          )),
          sortByName,
        )(n.subAttackPatterns.edges),
        killChainPhasesIds: R.map((o) => o.node.id, n.killChainPhases.edges),
      })),
      R.filter(filterSubattackPattern),
      R.filter(filterByKeyword),
      R.filter((o) => (currentModeOnlyActive ? o.level > 0 : o.level >= 0)),
    )(data.attackPatterns.edges);
    const killChainPhases = R.pipe(
      R.map((n) => R.map((o) => o.node, n.node.killChainPhases.edges)),
      R.flatten,
      R.uniq,
      R.filter((n) => n.kill_chain_name === currentKillChain),
      sortByOrder,
    )(data.attackPatterns.edges);
    const killChains = R.uniq([
      'mitre-attack',
      ...R.pipe(
        R.map((n) => R.map((o) => o.node, n.node.killChainPhases.edges)),
        R.flatten,
        R.map((n) => n.kill_chain_name),
      )(data.attackPatterns.edges),
    ]);
    const attackPatternsOfPhases = R.map(
      (n) => ({
        ...n,
        attackPatterns: R.pipe(
          R.filter((o) => R.includes(n.id, o.killChainPhasesIds)),
          sortByName,
        )(attackPatterns),
      }),
      killChainPhases,
    );
    return (
      <div
        className={
          marginRight ? classes.containerWithMarginRight : classes.container
        }
      >
        <AttackPtternsMatrixBar
          currentModeOnlyActive={currentModeOnlyActive}
          handleToggleModeOnlyActive={this.handleToggleModeOnlyActive.bind(
            this,
          )}
          currentKillChain={currentKillChain}
          handleChangeKillChain={this.handleChangeKillChain.bind(this)}
          killChains={killChains}
        />
        <div className={classes.header}>
          {attackPatternsOfPhases.map((k) => (
            <div key={k.id} className={classes.headerElement}>
              <div className={classes.title}>{truncate(k.phase_name, 18)}</div>
              <span className={classes.subtitle}>{`${
                k.attackPatterns.length
              } ${t('techniques')}`}</span>
            </div>
          ))}
        </div>
        <div className={classes.body}>
          {attackPatternsOfPhases.map((k) => (
            <div key={k.id} className={classes.column}>
              {k.attackPatterns.map((a) => (
                <div
                  key={a.id}
                  className={classes.element}
                  style={{
                    border: `1px solid ${colors[a.level][0]}`,
                    backgroundColor: colors[a.level][1],
                  }}
                >
                  <div className={classes.name}>{a.name}</div>
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>
    );
  }
}

AttackPatternsMatrixColumnsComponent.propTypes = {
  data: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
  attackPatterns: PropTypes.array,
  marginRight: PropTypes.bool,
  searchTerm: PropTypes.string,
};

export const attackPatternsMatrixColumnsQuery = graphql`
  query AttackPatternsMatrixColumnsQuery(
    $orderBy: AttackPatternsOrdering
    $orderMode: OrderingMode
    $count: Int!
    $cursor: ID
    $filters: [AttackPatternsFiltering]
  ) {
    ...AttackPatternsMatrixColumns_data
      @arguments(
        orderBy: $orderBy
        orderMode: $orderMode
        count: $count
        cursor: $cursor
        filters: $filters
      )
  }
`;

const AttackPatternsMatrixColumns = createRefetchContainer(
  AttackPatternsMatrixColumnsComponent,
  {
    data: graphql`
      fragment AttackPatternsMatrixColumns_data on Query
      @argumentDefinitions(
        orderBy: { type: "AttackPatternsOrdering", defaultValue: x_mitre_id }
        orderMode: { type: "OrderingMode", defaultValue: asc }
        count: { type: "Int", defaultValue: 25 }
        cursor: { type: "ID" }
        filters: { type: "[AttackPatternsFiltering]" }
      ) {
        attackPatterns(
          orderBy: $orderBy
          orderMode: $orderMode
          first: $count
          after: $cursor
          filters: $filters
        ) {
          edges {
            node {
              id
              name
              description
              isSubAttackPattern
              x_mitre_id
              subAttackPatterns {
                edges {
                  node {
                    id
                    name
                    description
                    x_mitre_id
                  }
                }
              }
              killChainPhases {
                edges {
                  node {
                    id
                    kill_chain_name
                    phase_name
                    x_opencti_order
                  }
                }
              }
            }
          }
        }
      }
    `,
  },
  attackPatternsLinesQuery,
);

export default R.compose(
  inject18n,
  withStyles(styles),
)(AttackPatternsMatrixColumns);
