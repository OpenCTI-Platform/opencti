import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, assoc } from 'ramda';
import { graphql } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import withTheme from '@mui/styles/withTheme';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import TableContainer from '@mui/material/TableContainer';
import Table from '@mui/material/Table';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import TableCell from '@mui/material/TableCell';
import TableBody from '@mui/material/TableBody';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import ItemIcon from '../../../../components/ItemIcon';

const styles = () => ({
  container: {
    width: '100%',
    height: '100%',
    overflow: 'auto',
    paddingBottom: 10,
  },
  paper: {
    height: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    borderRadius: 6,
  },
});

const entityStixCoreRelationshipsListDistributionQuery = graphql`
  query EntityStixCoreRelationshipsListDistributionQuery(
    $fromId: StixRef
    $relationship_type: String!
    $toTypes: [String]
    $isTo: Boolean
    $field: String!
    $operation: StatsOperation!
    $limit: Int
    $startDate: DateTime
    $endDate: DateTime
  ) {
    stixCoreRelationshipsDistribution(
      fromId: $fromId
      relationship_type: $relationship_type
      toTypes: $toTypes
      isTo: $isTo
      field: $field
      operation: $operation
      limit: $limit
      startDate: $startDate
      endDate: $endDate
    ) {
      label
      value
      entity {
        ... on BasicObject {
          entity_type
        }
        ... on AttackPattern {
          name
          description
        }
        ... on Campaign {
          name
          description
        }
        ... on CourseOfAction {
          name
          description
        }
        ... on Individual {
          name
          description
        }
        ... on Organization {
          name
          description
        }
        ... on Sector {
          name
          description
        }
        ... on System {
          name
          description
        }
        ... on Indicator {
          name
          description
        }
        ... on Infrastructure {
          name
          description
        }
        ... on IntrusionSet {
          name
          description
        }
        ... on Position {
          name
          description
        }
        ... on City {
          name
          description
        }
        ... on Country {
          name
          description
        }
        ... on Region {
          name
          description
        }
        ... on Malware {
          name
          description
        }
        ... on ThreatActor {
          name
          description
        }
        ... on Tool {
          name
          description
        }
        ... on Vulnerability {
          name
          description
        }
        ... on Incident {
          name
          description
        }
        ... on Event {
          name
          description
        }
        ... on Channel {
          name
          description
        }
        ... on Narrative {
          name
          description
        }
        ... on Language {
          name
        }
      }
    }
  }
`;

class EntityStixCoreRelationshipsList extends Component {
  renderContent() {
    const {
      t,
      stixCoreObjectId,
      relationshipType,
      toTypes,
      field,
      isTo,
      startDate,
      endDate,
      classes,
    } = this.props;
    const stixCoreRelationshipsDistributionVariables = {
      fromId: stixCoreObjectId,
      relationship_type: relationshipType,
      toTypes,
      field: field || 'entity_type',
      operation: 'count',
      limit: 10,
      isTo: isTo || false,
      startDate,
      endDate,
    };
    return (
      <QueryRenderer
        query={entityStixCoreRelationshipsListDistributionQuery}
        variables={stixCoreRelationshipsDistributionVariables}
        render={({ props }) => {
          if (
            props
            && props.stixCoreRelationshipsDistribution
            && props.stixCoreRelationshipsDistribution.length > 0
          ) {
            let data = props.stixCoreRelationshipsDistribution;
            if (field === 'internal_id') {
              data = map(
                (n) => assoc(
                  'label',
                  `[${t(`entity_${n.entity.entity_type}`)}] ${n.entity.name}`,
                  n,
                ),
                props.stixCoreRelationshipsDistribution,
              );
            }
            return (
              <div id="container" className={classes.container}>
                <TableContainer>
                  <Table size="small" style={{ width: '100%' }}>
                    <TableHead>
                      <TableRow>
                        <TableCell style={{ width: 50 }} align="center">
                          {' '}
                          #{' '}
                        </TableCell>
                        <TableCell>{t('Entity')}</TableCell>
                        <TableCell align="right">{t('Number')}</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {data.map((row) => (
                        <TableRow key={row.label}>
                          <TableCell align="center" style={{ width: 50 }}>
                            <ItemIcon
                              type={
                                field === 'internal_id'
                                  ? row.entity.entity_type
                                  : 'Stix-Cyber-Observable'
                              }
                            />
                          </TableCell>
                          <TableCell align="left">
                            {field === 'internal_id'
                              ? row.entity.name
                              : row.label}
                          </TableCell>
                          <TableCell align="right">{row.value}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </div>
            );
          }
          if (props) {
            return (
              <div style={{ display: 'table', height: '100%', width: '100%' }}>
                <span
                  style={{
                    display: 'table-cell',
                    verticalAlign: 'middle',
                    textAlign: 'center',
                  }}
                >
                  {t('No entities of this type has been found.')}
                </span>
              </div>
            );
          }
          return (
            <div style={{ display: 'table', height: '100%', width: '100%' }}>
              <span
                style={{
                  display: 'table-cell',
                  verticalAlign: 'middle',
                  textAlign: 'center',
                }}
              >
                <CircularProgress size={40} thickness={2} />
              </span>
            </div>
          );
        }}
      />
    );
  }

  render() {
    const { t, classes, title, variant } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{
            margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
          }}
        >
          {title || t('StixDomainObjects distribution')}
        </Typography>
        {variant !== 'inLine' ? (
          <Paper classes={{ root: classes.paper }} variant="outlined">
            {this.renderContent()}
          </Paper>
        ) : (
          this.renderContent()
        )}
      </div>
    );
  }
}

EntityStixCoreRelationshipsList.propTypes = {
  stixCoreObjectId: PropTypes.string,
  relationshipType: PropTypes.string,
  toTypes: PropTypes.array,
  title: PropTypes.string,
  field: PropTypes.string,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  isTo: PropTypes.bool,
  variant: PropTypes.string,
  startDate: PropTypes.string,
  endDate: PropTypes.string,
};

export default compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(EntityStixCoreRelationshipsList);
