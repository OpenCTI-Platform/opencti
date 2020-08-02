import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, propOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemMarking from '../../../../components/ItemMarking';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class XOpenCTIIncidentOverviewComponent extends Component {
  render() {
    const {
      t, fldt, classes, XOpenCTIIncident,
    } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Marking')}
          </Typography>
          {XOpenCTIIncident.objectMarking.edges.length > 0 ? (
            map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                />
              ),
              XOpenCTIIncident.objectMarking.edges,
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
          {fldt(XOpenCTIIncident.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fldt(XOpenCTIIncident.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor createdBy={propOr(null, 'createdBy', XOpenCTIIncident)} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <ExpandableMarkdown
            className="markdown"
            source={XOpenCTIIncident.description}
            limit={250}
          />
        </Paper>
      </div>
    );
  }
}

XOpenCTIIncidentOverviewComponent.propTypes = {
  XOpenCTIIncident: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const XOpenCTIXOpenCTIIncidentOverview = createFragmentContainer(
  XOpenCTIIncidentOverviewComponent,
  {
    XOpenCTIIncident: graphql`
      fragment XOpenCTIIncidentOverview_XOpenCTIIncident on XOpenCTIIncident {
        id
        name
        description
        created
        modified
        objectMarking {
          edges {
            node {
              id
              definition
            }
          }
        }
        createdBy {
          ... on Identity {
            id
            name
            entity_type
          }
        }
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(XOpenCTIXOpenCTIIncidentOverview);
