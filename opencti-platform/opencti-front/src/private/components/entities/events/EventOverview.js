import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose, propOr } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import Markdown from 'react-markdown';
import withStyles from '@mui/styles/withStyles';
import Paper from '@mui/material/Paper';
import Typography from '@mui/material/Typography';
import remarkGfm from 'remark-gfm';
import remarkParse from 'remark-parse';
import inject18n from '../../../../components/i18n';
import ItemAuthor from '../../../../components/ItemAuthor';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class EventOverviewComponent extends Component {
  render() {
    const { t, fldt, classes, event } = this.props;
    return (
      <div style={{ height: '100%' }} className="break">
        <Typography variant="h4" gutterBottom={true}>
          {t('Information')}
        </Typography>
        <Paper classes={{ root: classes.paper }} variant="outlined">
          <Typography variant="h3" gutterBottom={true}>
            {t('Creation date')}
          </Typography>
          {fldt(event.created)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Modification date')}
          </Typography>
          {fldt(event.modified)}
          <Typography
            variant="h3"
            gutterBottom={true}
            style={{ marginTop: 20 }}
          >
            {t('Author')}
          </Typography>
          <ItemAuthor createdBy={propOr(null, 'createdBy', event)} />
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
            {event.description}
          </Markdown>
        </Paper>
      </div>
    );
  }
}

EventOverviewComponent.propTypes = {
  event: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fldt: PropTypes.func,
};

const EventOverview = createFragmentContainer(EventOverviewComponent, {
  event: graphql`
    fragment EventOverview_event on Event {
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
    }
  `,
});

export default compose(inject18n, withStyles(styles))(EventOverview);
