import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, propOr } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
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

class NarrativeOverviewComponent extends Component {
  render() {
    const { t, fldt, classes, narrative } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Typography variant="h3" gutterBottom={true}>
            {t('Marking')}
          </Typography>
          {narrative.objectMarking.edges.length > 0 ? (
            map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                  color={markingDefinition.node.x_opencti_color}
                />
              ),
              narrative.objectMarking.edges,
            )
          ) : (
            <ItemMarking label="TLP:CLEAR" />
          )}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Creation date')}
          </Typography>
          {fldt(narrative.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fldt(narrative.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor createdBy={propOr(null, 'createdBy', narrative)} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <ExpandableMarkdown
            className="markdown"
            source={narrative.description}
            limit={250}
          />
        </Paper>
      </div>
    );
  }
}

NarrativeOverviewComponent.propTypes = {
  narrative: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const NarrativeOverview = createFragmentContainer(NarrativeOverviewComponent, {
  narrative: graphql`
    fragment NarrativeOverview_narrative on Narrative {
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
            x_opencti_color
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
});

export default compose(inject18n, withStyles(styles))(NarrativeOverview);
