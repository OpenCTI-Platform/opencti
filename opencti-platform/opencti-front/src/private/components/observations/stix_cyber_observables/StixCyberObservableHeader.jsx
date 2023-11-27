import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import StixCoreObjectContainer from '../../common/stix_core_objects/StixCoreObjectContainer';
import StixCyberObservablePopover from './StixCyberObservablePopover';
import { truncate } from '../../../../utils/String';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';
import StixCoreObjectSharing from '../../common/stix_core_objects/StixCoreObjectSharing';
import useGranted, { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
  },
  actions: {
    margin: '-6px 0 0 0',
    float: 'right',
  },
  actionButtons: {
    display: 'flex',
  },
}));

const StixCyberObservableHeaderComponent = ({
  stixCyberObservable,
  isArtifact,
  disableSharing,
}) => {
  const classes = useStyles();
  const isKnowledgeUpdater = useGranted([KNOWLEDGE_KNUPDATE]);
  const isKnowledgeEnricher = useGranted([KNOWLEDGE_KNENRICHMENT]);
  return (
    <>
      <Typography
        variant="h1"
        gutterBottom={true}
        classes={{ root: classes.title }}
        data-testid="observable-title"
      >
        {truncate(stixCyberObservable.observable_value, 50)}
      </Typography>
      <div className={classes.actions}>
        <div className={classes.actionButtons}>
          {disableSharing !== true && (
            <StixCoreObjectSharing
              elementId={stixCyberObservable.id}
              variant="header"
            />
          )}
          {isKnowledgeUpdater && (
            <StixCoreObjectContainer elementId={stixCyberObservable.id} />
          )}
          {isKnowledgeEnricher && (
            <StixCoreObjectEnrichment stixCoreObjectId={stixCyberObservable.id} variant="button" />
          )}
          <StixCyberObservablePopover
            stixCyberObservableId={stixCyberObservable.id}
            isArtifact={isArtifact}
          />
        </div>
      </div>
      <div className="clearfix" />
    </>
  );
};

const StixCyberObservableHeader = createFragmentContainer(
  StixCyberObservableHeaderComponent,
  {
    stixCyberObservable: graphql`
      fragment StixCyberObservableHeader_stixCyberObservable on StixCyberObservable {
        id
        entity_type
        observable_value
      }
    `,
  },
);

export default StixCyberObservableHeader;
