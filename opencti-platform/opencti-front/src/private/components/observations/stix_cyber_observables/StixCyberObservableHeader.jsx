import React, { useState } from 'react';
import { graphql, createFragmentContainer } from 'react-relay';
import Typography from '@mui/material/Typography';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/material/styles';
import { MoreVert } from '@mui/icons-material';
import ToggleButton from '@mui/material/ToggleButton';
import StixCoreObjectSharingList from '../../common/stix_core_objects/StixCoreObjectSharingList';
import { DraftChip } from '../../common/draft/DraftChip';
import StixCoreObjectEnrollPlaybook from '../../common/stix_core_objects/StixCoreObjectEnrollPlaybook';
import StixCoreObjectContainer from '../../common/stix_core_objects/StixCoreObjectContainer';
import { truncate } from '../../../../utils/String';
import StixCoreObjectEnrichment from '../../common/stix_core_objects/StixCoreObjectEnrichment';
import StixCoreObjectSharing from '../../common/stix_core_objects/StixCoreObjectSharing';
import useGranted, { KNOWLEDGE_KNENRICHMENT, KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import StixCyberObservableEdition from './StixCyberObservableEdition';
import Security from '../../../../utils/Security';
import { useFormatter } from '../../../../components/i18n';
import stopEvent from '../../../../utils/domEvent';

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

const StixCyberObservableHeaderComponent = ({ stixCyberObservable }) => {
  const theme = useTheme();
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [anchorPopover, setAnchorPopover] = useState(null);
  const [openSharing, setOpenSharing] = useState(false);

  const isKnowledgeUpdater = useGranted([KNOWLEDGE_KNUPDATE]);
  const isKnowledgeEnricher = useGranted([KNOWLEDGE_KNENRICHMENT]);

  const onOpenPopover = (event) => {
    stopEvent(event);
    setAnchorPopover(event.currentTarget);
  };

  const onClosePopover = (event) => {
    stopEvent(event);
    setAnchorPopover(null);
  };

  const onOpenSharing = () => {
    setOpenSharing(true);
    setAnchorPopover(null);
  };

  return (
    <>
      <Typography
        variant="h1"
        gutterBottom
        classes={{ root: classes.title }}
        style={{ marginRight: theme.spacing(1) }}
      >
        {truncate(stixCyberObservable.observable_value, 50)}
      </Typography>

      {stixCyberObservable.draftVersion && <DraftChip />}

      <div className={classes.actions}>
        <div className={classes.actionButtons}>
          <StixCoreObjectSharingList data={stixCyberObservable} />

          {isKnowledgeUpdater && (
            <StixCoreObjectContainer elementId={stixCyberObservable.id} />
          )}
          {isKnowledgeEnricher && (
            <StixCoreObjectEnrichment stixCoreObjectId={stixCyberObservable.id} />
          )}
          <StixCoreObjectEnrollPlaybook stixCoreObjectId={stixCyberObservable.id} />

          <ToggleButton
            onClick={onOpenPopover}
            aria-label={t_i18n('Popover of actions')}
            value="popover"
            aria-haspopup="true"
            size="small"
            color="primary"
          >
            <MoreVert fontSize="small" color="primary" />
          </ToggleButton>
          <Menu
            anchorEl={anchorPopover}
            open={Boolean(anchorPopover)}
            onClose={onClosePopover}
            aria-label={t_i18n('Popover menu')}
          >
            <MenuItem onClick={onOpenSharing}>
              {t_i18n('Share with an organization')}
            </MenuItem>
          </Menu>

          <Security needs={[KNOWLEDGE_KNUPDATE]}>
            <StixCyberObservableEdition
              stixCyberObservableId={stixCyberObservable.id}
            />
          </Security>

          <StixCoreObjectSharing
            elementId={stixCyberObservable.id}
            open={openSharing}
            variant="header"
            handleClose={() => setOpenSharing(false)}
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
        draftVersion {
          draft_id
          draft_operation
        }
        entity_type
        observable_value
        ...StixCoreObjectSharingListFragment
      }
    `,
  },
);

export default StixCyberObservableHeader;
