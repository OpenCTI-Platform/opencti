import React from 'react';
import { compose } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import Grid from '@material-ui/core/Grid';
import Typography from '@material-ui/core/Typography';
import { withStyles } from '@material-ui/core';
import inject18n from '../../../../components/i18n';
import StixObservableHeader from './StixObservableHeader';
import StixObservableKnowledgeEntities from './StixObservableKnowledgeEntities';
import StixObservableEnrichment from './StixObservableEnrichment';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

const StixObservableKnowledge = (props) => {
  const { stixObservable, classes, t } = props;
  return (
    <div className={classes.container}>
      <StixObservableHeader stixObservable={stixObservable} />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={9}>
          <StixObservableKnowledgeEntities entityId={stixObservable.id} />
        </Grid>
        <Grid item={true} xs={3}>
          <Typography variant="h4" gutterBottom={true}>
            {t('Enrichment connectors')}
          </Typography>
          <StixObservableEnrichment stixObservable={stixObservable} />
        </Grid>
      </Grid>
    </div>
  );
};

const StixObservableKnowledgeFragment = createFragmentContainer(
  StixObservableKnowledge,
  {
    stixObservable: graphql`
      fragment StixObservableKnowledge_stixObservable on StixObservable {
        id
        entity_type
        ...StixObservableEnrichment_stixObservable
        ...StixObservableHeader_stixObservable
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixObservableKnowledgeFragment);
