import React from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import StixCyberObservablePopover from './StixCyberObservablePopover';
import { truncate } from '../../../../utils/String';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';
import StixCoreObjectSharing from '../../common/stix_core_objects/StixCoreObjectSharing';

const useStyles = makeStyles((theme) => ({
  title: {
    float: 'left',
    color: theme.palette.mode === 'light'
      ? theme.palette.common.black
      : theme.palette.primary.main,
    fontSize: '24px',
    fontWeight: 'bold',
  },
  popover: {
    float: 'left',
    marginTop: '-13px',
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
        <div className={classes.actionButtons}>
          {disableSharing !== true && (
            <StixCoreObjectSharing
              elementId={stixCyberObservable.id}
              variant="header"
            />
          )}
          <StixCoreObjectEnrichment stixCoreObjectId={stixCyberObservable.id} />
        </div>
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
