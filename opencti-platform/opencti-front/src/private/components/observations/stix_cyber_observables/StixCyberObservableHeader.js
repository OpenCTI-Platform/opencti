import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import StixCyberObservablePopover from './StixCyberObservablePopover';
import { truncate } from '../../../../utils/String';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';

const useStyles = makeStyles(() => ({
  title: {
    float: 'left',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
  },
  marking: {
    float: 'right',
    overflowX: 'hidden',
  },
}));

const StixCyberObservableHeaderComponent = ({
  stixCyberObservable,
  isArtifact,
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
      <StixCoreObjectEnrichment stixCoreObjectId={stixCyberObservable.id} />
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
