import React, { FunctionComponent, useState } from 'react';
import { createFragmentContainer, graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import makeStyles from '@mui/styles/makeStyles';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import RoleEditionOverview from './RoleEditionOverview';
import RoleEditionCapabilities, { roleEditionCapabilitiesLinesSearch } from './RoleEditionCapabilities';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import {
  RoleEditionCapabilitiesLinesSearchQuery,
} from './__generated__/RoleEditionCapabilitiesLinesSearchQuery.graphql';
import { RoleEdition_role$data } from './__generated__/RoleEdition_role.graphql';
import { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    padding: '20px 20px 20px 60px',
    backgroundColor: theme.palette.background.paper,
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  title: {
    float: 'left',
  },
}));

interface RoleEditionProps {
  role: RoleEdition_role$data,
  handleClose: () => void,
}

const RoleEdition: FunctionComponent<RoleEditionProps> = ({ handleClose, role }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [currentTab, setTab] = useState(0);
  const { editContext } = role;

  const queryRef = useQueryLoading<RoleEditionCapabilitiesLinesSearchQuery>(roleEditionCapabilitiesLinesSearch);

  return (
      <div>
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleClose}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update a role')}
          </Typography>
          <SubscriptionAvatars context={editContext} />
          <div className="clearfix" />
        </div>
        <div className={classes.container}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={currentTab} onChange={(event, value) => setTab(value)}>
              <Tab label={t('Overview')} />
              <Tab label={t('Capabilities')} />
            </Tabs>
          </Box>
           {currentTab === 0 && <RoleEditionOverview role={role} context={editContext} />}
           {currentTab === 1 && queryRef && (
               <React.Suspense
                 fallback={<Loader variant={LoaderVariant.inElement} />}
               >
                 <RoleEditionCapabilities role={role} queryRef={queryRef} />
               </React.Suspense>
           )}
        </div>
      </div>
  );
};

const RoleEditionFragment = createFragmentContainer(RoleEdition, {
  role: graphql`
    fragment RoleEdition_role on Role {
      id
      ...RoleEditionOverview_role
      ...RoleEditionCapabilities_role
      editContext {
        name
        focusOn
      }
    }
  `,
});

export default RoleEditionFragment;
