import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, map, propOr } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import Markdown from 'react-markdown';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';
import ItemMarking from '../../../../components/ItemMarking';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class SystemOverviewComponent extends Component {
  render() {
    const { t, fldt, classes, system } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Typography variant="h3" gutterBottom={true}>
            {t('Marking')}
          </Typography>
          {system.objectMarking.edges.length > 0 ? (
            map(
              (markingDefinition) => (
                <ItemMarking
                  key={markingDefinition.node.id}
                  label={markingDefinition.node.definition}
                  color={markingDefinition.node.x_opencti_color}
                />
              ),
              system.objectMarking.edges,
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
          {fldt(system.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fldt(system.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor createdBy={propOr(null, 'createdBy', system)} />
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Description')}
          </Typography>
          <Markdown
            remarkPlugins={[remarkGfm, remarkParse]}
            parserOptions={{ commonmark: true }}
            className="markdown"
          >
            {system.description}
          </Markdown>
        </Paper>
      </div>
    );
  }
}

SystemOverviewComponent.propTypes = {
  system: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const SystemOverview = createFragmentContainer(SystemOverviewComponent, {
  system: graphql`
    fragment SystemOverview_system on System {
      id
      name
      description
      created
      modified
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
            id
            definition
            x_opencti_color
          }
        }
      }
    }
  `,
});

export default compose(inject18n, withStyles(styles))(SystemOverview);
