import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, head, map } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { DiagramEngine } from 'storm-react-diagrams';
import Drawer from '@material-ui/core/Drawer';
import Grid from '@material-ui/core/Grid';
import Select from '@material-ui/core/Select';
import Chip from '@material-ui/core/Chip';
import MenuItem from '@material-ui/core/MenuItem';
import FormControlLabel from '@material-ui/core/FormControlLabel';
import Switch from '@material-ui/core/Switch';
import { withStyles } from '@material-ui/core/styles';
import { QueryRenderer, fetchQuery } from '../../../relay/environment';
import { currentYear, parse, yearFormat } from '../../../utils/Time';
import inject18n from '../../../components/i18n';
import EntityLabelFactory from '../../../components/graph_node/EntityLabelFactory';
import EntityLinkFactory from '../../../components/graph_node/EntityLinkFactory';
import EntityNodeFactory from '../../../components/graph_node/EntityNodeFactory';
import EntityPortFactory from '../../../components/graph_node/EntityPortFactory';
import StixDomainEntityKnowledgeGraph from './StixDomainEntityKnowledgeGraph';

const styles = theme => ({
  container: {
    width: '100%',
    height: '100%',
    margin: 0,
    padding: 0,
    position: 'relative',
  },
  bottomNav: {
    zIndex: 1000,
    padding: '10px 274px 10px 84px',
    backgroundColor: theme.palette.navBottom.background,
    display: 'flex',
  },
  chips: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  chip: {
    margin: theme.spacing.unit / 4,
  },
});

const firstStixRelationQuery = graphql`
    query StixDomainEntityKnowledgeFirstStixRelationQuery($fromId: String, $first: Int, $orderBy: StixRelationsOrdering, $orderMode: OrderingMode) {
        stixRelations(fromId: $fromId, first: $first, orderBy: $orderBy, orderMode: $orderMode) {
            edges {
                node {
                    id
                    first_seen
                }
            }
        }
    }
`;

const stixDomainEntityKnowledgeQuery = graphql`
    query StixDomainEntityKnowledgeQuery($id: String!, $count: Int, $inferred: Boolean, $toTypes: [String], $firstSeenStart: DateTime, $firstSeenStop: DateTime, $lastSeenStart: DateTime, $lastSeenStop: DateTime, $weights: [Int]) {
        stixDomainEntity(id: $id) {
            ...StixDomainEntityKnowledgeGraph_stixDomainEntity @arguments(toTypes: $toTypes, inferred: $inferred, firstSeenStart: $firstSeenStart, firstSeenStop: $firstSeenStop, lastSeenStart: $lastSeenStart, lastSeenStop: $lastSeenStop, weights: $weights, first: $count)
        }
    }
`;

class StixDomainEntityKnowledge extends Component {
  constructor(props) {
    super(props);
    const engine = new DiagramEngine();
    engine.installDefaultFactories();
    engine.registerPortFactory(new EntityPortFactory());
    engine.registerNodeFactory(new EntityNodeFactory());
    engine.registerLinkFactory(new EntityLinkFactory());
    engine.registerLabelFactory(new EntityLabelFactory());
    this.state = {
      engine,
      inferred: true,
      firstSeen: 'All years',
      firstSeenFirstYear: currentYear(),
      firstSeenStart: null,
      firstSeenStop: null,
    };
  }

  componentDidMount() {
    const { stixDomainEntityId } = this.props;
    fetchQuery(firstStixRelationQuery, {
      inferred: true,
      fromId: stixDomainEntityId,
      first: 1,
      orderBy: 'first_seen',
      orderMode: 'asc',
    }).then((data) => {
      if (data.stixRelations.edges && data.stixRelations.edges.length > 0) {
        this.setState({ firstSeenFirstYear: yearFormat(head(data.stixRelations.edges).node.first_seen) });
      }
    });
  }

  handleChangeYear(event) {
    const { value } = event.target;
    if (value !== 'All years') {
      const startDate = `${value}-01-01`;
      const endDate = `${value}-12-31`;
      this.setState({
        firstSeen: value,
        firstSeenStart: parse(startDate).format(),
        firstSeenStop: parse(endDate).format(),
      });
    } else {
      this.setState({
        firstSeen: value,
        firstSeenStart: null,
        firstSeenStop: null,
      });
    }
  }

  handleChangeInferred() {
    this.setState({ inferred: !this.state.inferred });
  }

  render() {
    const { t, classes, stixDomainEntityId } = this.props;
    const startYear = this.state.firstSeenFirstYear === currentYear() ? this.state.firstSeenFirstYear - 1 : this.state.firstSeenFirstYear;
    const yearsList = [];
    for (let i = startYear; i <= currentYear(); i++) {
      yearsList.push(i);
    }
    const variables = {
      id: stixDomainEntityId,
      count: 100,
      inferred: this.state.inferred,
      toTypes: null,
      firstSeenStart: null,
      firstSeenStop: null,
    };

    return (
      <div className={classes.container}>
        <Drawer anchor='bottom' variant='permanent' classes={{ paper: classes.bottomNav }}>
          <Grid container={true} spacing={8}>
            <Grid item={true} xs='auto'>
              <Select
                style={{ width: 170, height: 50 }}
                value={this.state.firstSeen}
                onChange={this.handleChangeYear.bind(this)}
                renderValue={selected => (
                  <div className={classes.chips}>
                    <Chip key={selected} label={t(selected)} className={classes.chip}/>
                  </div>
                )}
              >
                <MenuItem value='All years'>{t('All years')}</MenuItem>
                {map(year => (<MenuItem key={year} value={year}>{year}</MenuItem>), yearsList)}
              </Select>
            </Grid>
            <Grid item={true} xs='auto'>
              <FormControlLabel
                style={{ paddingTop: 5, marginLeft: 20 }}
                control={
                  <Switch
                    checked={this.state.inferred}
                    onChange={this.handleChangeInferred.bind(this)}
                    color='primary'
                  />
                }
                label={t('Inferences')}
              />
            </Grid>
          </Grid>
        </Drawer>
        <QueryRenderer
          query={stixDomainEntityKnowledgeQuery}
          variables={variables}
          render={({ props }) => {
            if (props && props.stixDomainEntity) {
              return (
                <StixDomainEntityKnowledgeGraph
                  engine={this.state.engine}
                  variables={variables}
                  stixDomainEntity={props.stixDomainEntity}
                  firstSeenYear={this.state.firstSeenStart ? yearFormat(this.state.firstSeenStart) : 'all'}
                />
              );
            }
            return (
              <div> &nbsp; </div>
            );
          }}
        />
      </div>
    );
  }
}

StixDomainEntityKnowledge.propTypes = {
  stixDomainEntityId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(StixDomainEntityKnowledge);
