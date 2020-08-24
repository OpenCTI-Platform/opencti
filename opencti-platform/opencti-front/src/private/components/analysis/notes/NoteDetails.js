import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import { withStyles } from '@material-ui/core/styles';
import Paper from '@material-ui/core/Paper';
import Typography from '@material-ui/core/Typography';
import Markdown from 'react-markdown';
import Grid from '@material-ui/core/Grid';
import inject18n from '../../../../components/i18n';
import EntityStixCoreRelationshipsDonut from '../../common/stix_core_relationships/EntityStixCoreRelationshipsDonut';

const styles = () => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
});

class NoteDetailsComponent extends Component {
  render() {
    const { t, classes, note } = this.props;
    return (
      <div style={{ height: '100%' }}>
        <Typography variant="h4" gutterBottom={true}>
          {t('Entity details')}
        </Typography>
        <Paper classes={{ root: classes.paper }} elevation={2}>
          <Grid container={true} spacing={3}>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Content')}
              </Typography>
              <Markdown className="markdown" source={note.content} />
            </Grid>
            <Grid item={true} xs={6}>
              test
            </Grid>
          </Grid>
          <EntityStixCoreRelationshipsDonut
            variant="inLine"
            entityId={note.id}
            entityType="Stix-Core-Object"
            relationshipType="object"
            field="entity_type"
            height={200}
          />
        </Paper>
      </div>
    );
  }
}

NoteDetailsComponent.propTypes = {
  note: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  fld: PropTypes.func,
};

const NoteDetails = createFragmentContainer(NoteDetailsComponent, {
  note: graphql`
    fragment NoteDetails_note on Note {
      id
      attribute_abstract
      content
    }
  `,
});

export default compose(inject18n, withStyles(styles))(NoteDetails);
