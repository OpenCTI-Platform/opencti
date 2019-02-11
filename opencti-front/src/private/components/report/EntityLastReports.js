import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link } from 'react-router-dom';
import { compose, pathOr, head } from 'ramda';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import List from '@material-ui/core/List';
import ListItem from '@material-ui/core/ListItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { Description } from '@material-ui/icons';
import inject18n from '../../../components/i18n';
import ItemMarking from '../../../components/ItemMarking';
import { truncate } from '../../../utils/String';
import { QueryRenderer } from '../../../relay/environment';

const styles = theme => ({
  paper: {
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: 0,
    backgroundColor: theme.palette.paper.background,
    color: theme.palette.text.main,
    borderRadius: 6,
  },
  item: {
    height: 60,
    minHeight: 60,
    maxHeight: 60,
    transition: 'background-color 0.1s ease',
    paddingRight: 0,
    cursor: 'pointer',
    '&:hover': {
      background: 'rgba(0, 0, 0, 0.1)',
    },
  },
  itemIcon: {
    marginRight: 0,
    color: theme.palette.primary.main,
  },
});

const inlineStyles = {
  itemDate: {
    fontSize: 11,
    width: 80,
    minWidth: 80,
    maxWidth: 80,
    marginRight: 24,
    textAlign: 'right',
    color: '#ffffff',
  },
};

const entityLastReportsQuery = graphql`
    query EntityLastReportsQuery($objectId: String!, $first: Int) {
        reports(objectId: $objectId, first: $first) {
            edges {
                node {
                    id
                    name
                    description
                    published
                    markingDefinitions {
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

class EntityLastReports extends Component {
  render() {
    const {
      t, nsd, classes, entityId,
    } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant='h4' gutterBottom={true}>
          {t('Last reports')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <QueryRenderer
            query={entityLastReportsQuery}
            variables={{ objectId: entityId, first: 8 }}
            render={({ props }) => {
              if (props && props.reports) {
                return (
                  <List>
                    {props.reports.edges.map((reportEdge) => {
                      const report = reportEdge.node;
                      const markingDefinition = head(pathOr([], ['markingDefinitions', 'edges'], report));
                      return (
                        <ListItem
                          key={report.id}
                          dense={true}
                          classes={{ default: classes.item }}
                          divider={true}
                          component={Link}
                          to={`/dashboard/reports/all/${report.id}`}
                        >
                          <ListItemIcon classes={{ root: classes.itemIcon }}>
                            <Description/>
                          </ListItemIcon>
                          <ListItemText primary={truncate(report.name, 70)} secondary={truncate(report.description, 70)}/>
                          <div style={{ minWidth: 100 }}>
                            {markingDefinition ? <ItemMarking key={markingDefinition.node.id} label={markingDefinition.node.definition}/> : ''}
                          </div>
                          <div style={inlineStyles.itemDate}>{nsd(report.published)}</div>
                        </ListItem>
                      );
                    })}
                  </List>
                );
              }
              return (
                <div> &nbsp; </div>
              );
            }}
          />
        </Paper>
      </div>
    );
  }
}

EntityLastReports.propTypes = {
  entityId: PropTypes.string,
  classes: PropTypes.object,
  t: PropTypes.func,
  nsd: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(EntityLastReports);
