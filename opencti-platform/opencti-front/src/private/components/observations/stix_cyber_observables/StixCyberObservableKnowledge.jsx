import React from 'react';
import { compose } from 'ramda';
import { graphql, createFragmentContainer } from 'react-relay';
import withStyles from '@mui/styles/withStyles';
import inject18n from '../../../../components/i18n';
import StixCyberObservableHeader from './StixCyberObservableHeader';
import StixCyberObservableKnowledgeEntities from './StixCyberObservableEntities';
import StixCyberObservableNestedEntities from './StixCyberObservableNestedEntities';

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
  return (
    <div className={classes.container}>
      <StixCyberObservableHeader stixCyberObservable={stixCyberObservable} />
      <div style={{ marginTop: 20 }}>
        <StixCyberObservableNestedEntities
          entityId={stixCyberObservable.id}
          entityType={stixCyberObservable.entity_type}
        />
      </div>
      <div style={{ marginTop: 40 }}>
        <StixCyberObservableKnowledgeEntities
          entityId={stixCyberObservable.id}
        />
      </div>
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
