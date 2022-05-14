import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import * as R from 'ramda';
import { graphql } from 'react-relay';
import withTheme from '@mui/styles/withTheme';
import withStyles from '@mui/styles/withStyles';
import CircularProgress from '@mui/material/CircularProgress';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import { head, pathOr } from 'ramda';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import List from '@mui/material/List';
import ItemMarking from '../../../../components/ItemMarking';
import ItemIcon from '../../../../components/ItemIcon';
import inject18n from '../../../../components/i18n';
import { QueryRenderer } from '../../../../relay/environment';
import { resolveLink } from '../../../../utils/Entity';
import { defaultValue } from '../../../../utils/Graph';

const styles = (theme) => ({
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
  item: {
    height: 50,
    minHeight: 50,
    maxHeight: 50,
    paddingRight: 0,
  },
  itemText: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 10,
  },
  itemIcon: {
    marginRight: 0,
    color: theme.palette.primary.main,
  },
  itemIconDisabled: {
    marginRight: 0,
    color: theme.palette.grey[700],
  },
});

const inlineStyles = {
  itemAuthor: {
    width: 80,
    minWidth: 80,
    maxWidth: 80,
    marginRight: 24,
    marginLeft: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
  itemDate: {
    width: 80,
    minWidth: 80,
    maxWidth: 80,
    marginRight: 24,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
};

const stixDomainObjectsListQuery = graphql`
  query StixDomainObjectsListQuery(
    $types: [String]
    $first: Int
    $orderBy: StixDomainObjectsOrdering
    $orderMode: OrderingMode
    $filters: [StixDomainObjectsFiltering]
  ) {
    stixDomainObjects(
      types: $types
      first: $first
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
    ) {
      edges {
        node {
          entity_type
          created
          created_at
          modified
          ... on AttackPattern {
            name
            description
          }
          ... on Campaign {
            name
            description
          }
          ... on Note {
            attribute_abstract
          }
          ... on ObservedData {
            first_observed
            last_observed
          }
          ... on Opinion {
            opinion
          }
          ... on Report {
            name
            description
            published
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
          createdBy {
            ... on Identity {
              id
              name
              entity_type
            }
          }
          objectMarking {
            edges {
              node {
                definition
              }
            }
          }
        }
      }
    }
  }
`;

class StixDomainObjectsList extends Component {
  renderContent() {
    const { t, fsd, containerId, dateAttribute, classes, types } = this.props;
    const filters = [];
    if (containerId) {
      filters.push({
        key: 'objectContains',
        values: [containerId],
      });
    }
    return (
      <QueryRenderer
        query={stixDomainObjectsListQuery}
        variables={{
          types: types || ['Stix-Domain-Object'],
          first: 10,
          orderBy: dateAttribute,
          orderMode: 'desc',
          filters,
        }}
        render={({ props }) => {
          if (
            props
            && props.stixDomainObjects
            && props.stixDomainObjects.edges.length > 0
          ) {
            const data = props.stixDomainObjects.edges;
            return (
              <div id="container" className={classes.container}>
                <List>
                  {data.map((stixCoreObjectEdge) => {
                    const stixCoreObject = stixCoreObjectEdge.node;
                    const markingDefinition = head(
                      pathOr([], ['objectMarking', 'edges'], stixCoreObject),
                    );
                    return (
                      <ListItem
                        key={stixCoreObject.id}
                        dense={true}
                        button={true}
                        classes={{ root: classes.item }}
                        divider={true}
                        component={Link}
                        to={`${resolveLink(stixCoreObject.entity_type)}/${
                          stixCoreObject.id
                        }`}
                      >
                        <ListItemIcon>
                          <ItemIcon
                            type={stixCoreObject.entity_type}
                            color="primary"
                          />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <div className={classes.itemText}>
                              {defaultValue(stixCoreObject)}
                            </div>
                          }
                        />
                        <div style={inlineStyles.itemAuthor}>
                          {pathOr('', ['createdBy', 'name'], stixCoreObject)}
                        </div>
                        <div style={inlineStyles.itemDate}>
                          {fsd(stixCoreObject[dateAttribute])}
                        </div>
                        <div style={{ width: 110, paddingRight: 20 }}>
                          {markingDefinition && (
                            <ItemMarking
                              key={markingDefinition.node.id}
                              label={markingDefinition.node.definition}
                              variant="inList"
                            />
                          )}
                        </div>
                      </ListItem>
                    );
                  })}
                </List>
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
    const { t, classes, title, variant, height } = this.props;
    return (
      <div style={{ height: height || '100%' }}>
        <Typography
          variant="h4"
          gutterBottom={true}
          style={{
            margin: variant !== 'inLine' ? '0 0 10px 0' : '-10px 0 10px -7px',
          }}
        >
          {title || t('Reports list')}
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

StixDomainObjectsList.propTypes = {
  title: PropTypes.string,
  containerId: PropTypes.string,
  types: PropTypes.array,
  classes: PropTypes.object,
  theme: PropTypes.object,
  t: PropTypes.func,
  height: PropTypes.number,
  dateAttribute: PropTypes.string,
  variant: PropTypes.string,
};

export default R.compose(
  inject18n,
  withTheme,
  withStyles(styles),
)(StixDomainObjectsList);
