import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import StixCyberObservablePopover from './StixCyberObservablePopover';
import { truncate } from '../../../../utils/String';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';
import StixCoreObjectSharing from '../../common/stix_core_objects/StixCoreObjectSharing';

const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  actions: {
    margin: '-6px 0 0 0',
    float: 'right',
  },
}));

const StixCyberObservableHeaderComponent = ({
  stixCyberObservable,
  isArtifact,
  disableSharing,
}) => {
  const classes = useStyles();
  return (
    <div>
      <Typography
        variant="h1"
        gutterBottom={true}
        classes={{ root: classes.title }}
      >
        {truncate(stixCyberObservable.observable_value, 50)}
      </Typography>
      <div className={classes.popover}>
        <StixCyberObservablePopover
          stixCyberObservableId={stixCyberObservable.id}
          isArtifact={isArtifact}
        />
      </div>
      <div className={classes.actions}>
        <ToggleButtonGroup size="small" color="secondary" exclusive={true}>
          {disableSharing !== true && (
            <StixCoreObjectSharing
              elementId={stixCyberObservable.id}
              variant="header"
            />
          )}
          <StixCoreObjectEnrichment stixCoreObjectId={stixCyberObservable.id} />
        </ToggleButtonGroup>
      </div>
      <div className="clearfix" />
    </div>
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
