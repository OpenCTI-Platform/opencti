import React from 'react';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import Grid from '@mui/material/Grid';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import StixCyberObservableHeader from './StixCyberObservableHeader';
import StixCyberObservableKnowledgeEntities from './StixCyberObservableKnowledgeEntities';
import { QueryRenderer } from '../../../../relay/environment';
import StixCyberObservableLinks, {
  stixCyberObservableLinksQuery,
} from './StixCyberObservableLinks';
import StixCyberObservableIndicators from './StixCyberObservableIndicators';

const styles = () => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
});

const StixCyberObservableKnowledge = (props) => {
  const { stixCyberObservable, classes } = props;
  const paginationOptions = {
    elementId: stixCyberObservable.id,
    orderBy: 'created_at',
    orderMode: 'desc',
  };
  return (
    <div className={classes.container}>
      <StixCyberObservableHeader stixCyberObservable={stixCyberObservable} />
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10, marginBottom: 40 }}>
          <QueryRenderer
            query={stixCyberObservableLinksQuery}
            variables={{ count: 25, ...paginationOptions }}
            render={({ props: queryProps }) => (
              <StixCyberObservableLinks
                stixCyberObservableId={stixCyberObservable.id}
                stixCyberObservableType={stixCyberObservable.entity_type}
                paginationOptions={paginationOptions}
                data={queryProps}
              />
            )}
          />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10, marginBottom: 40 }}>
          <StixCyberObservableIndicators
            paginationOptions={paginationOptions}
            stixCyberObservable={stixCyberObservable}
          />
        </Grid>
        <Grid item={true} xs={12}>
          <StixCyberObservableKnowledgeEntities
            entityId={stixCyberObservable.id}
          />
        </Grid>
      </Grid>
    </div>
  );
};

const StixCyberObservableKnowledgeFragment = createFragmentContainer(
  StixCyberObservableKnowledge,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableKnowledge_stixCyberObservable on StixCyberObservable {
        id
        entity_type
        ...StixCyberObservableHeader_stixCyberObservable
        ...StixCyberObservableIndicators_stixCyberObservable
      }
    `,
  },
);

export default compose(
  inject18n,
  withStyles(styles),
)(StixCyberObservableKnowledgeFragment);
