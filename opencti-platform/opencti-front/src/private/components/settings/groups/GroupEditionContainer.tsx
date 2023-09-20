import React, { FunctionComponent, useState } from 'react';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, PreloadedQuery, useFragment, usePreloadedQuery } from 'react-relay';
import { SubscriptionAvatars } from '../../../../components/Subscription';
import GroupEditionOverview from './GroupEditionOverview';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import GroupEditionRoles, { groupEditionRolesLinesSearchQuery } from './GroupEditionRoles';
import GroupEditionUsers from './GroupEditionUsers';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { GroupEditionRolesLinesSearchQuery } from './__generated__/GroupEditionRolesLinesSearchQuery.graphql';
import { GroupEditionContainerQuery } from './__generated__/GroupEditionContainerQuery.graphql';
import { GroupEditionContainer_group$key } from './__generated__/GroupEditionContainer_group.graphql';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import GroupEditionMarkings from './GroupEditionMarkings';

const useStyles = makeStyles<Theme>((theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
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

export const groupEditionContainerQuery = graphql`
    query GroupEditionContainerQuery($id: String!) {
        group(id: $id) {
            ...GroupEditionContainer_group
        }
    }
`;

const GroupEditionContainerFragment = graphql`
      fragment GroupEditionContainer_group on Group
      @argumentDefinitions(
          rolesOrderBy: { type: "RolesOrdering", defaultValue: name }
          rolesOrderMode: { type: "OrderingMode", defaultValue: asc }
      ) {
          id
          ...GroupEditionOverview_group
          ...GroupEditionMarkings_group
          ...GroupEditionUsers_group
          ...GroupEditionRoles_group
          @arguments(
              orderBy: $rolesOrderBy
              orderMode: $rolesOrderMode
          )
          editContext {
              name
              focusOn
          }
      }
  `;

interface GroupEditionContainerProps {
  groupQueryRef: PreloadedQuery<GroupEditionContainerQuery>,
  handleClose: () => void,
}

const GroupEditionContainer: FunctionComponent<GroupEditionContainerProps> = ({ groupQueryRef, handleClose }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const [currentTab, setTab] = useState(0);
  const groupData = usePreloadedQuery<GroupEditionContainerQuery>(groupEditionContainerQuery, groupQueryRef);
  const roleQueryRef = useQueryLoading<GroupEditionRolesLinesSearchQuery>(groupEditionRolesLinesSearchQuery);
  if (groupData.group) {
    const group = useFragment<GroupEditionContainer_group$key>(
      GroupEditionContainerFragment,
      groupData.group,
    );
    const { editContext } = group;
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
            <Close fontSize="small" color="primary"/>
          </IconButton>
          <Typography variant="h6" classes={{ root: classes.title }}>
            {t('Update a group')}
          </Typography>
          <SubscriptionAvatars context={editContext}/>
          <div className="clearfix"/>
        </div>
        <div className={classes.container}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={currentTab} onChange={(event, value) => setTab(value)}>
              <Tab label={t('Overview')}/>
              <Tab label={t('Roles')}/>
              <Tab label={t('Markings')}/>
              <Tab label={t('Members')}/>
            </Tabs>
          </Box>
          {currentTab === 0 && (
            <GroupEditionOverview group={group} context={editContext}/>
          )}
          {currentTab === 1 && roleQueryRef && (
            <React.Suspense
              fallback={<Loader variant={LoaderVariant.inElement}/>}
            >
              <GroupEditionRoles group={group} queryRef={roleQueryRef}/>
            </React.Suspense>
          )}
          {currentTab === 2 && <GroupEditionMarkings group={group}/>}
          {currentTab === 3 && <GroupEditionUsers group={group}/>}
        </div>
      </div>
    );
  }
  return <ErrorNotFound />;
};

export default GroupEditionContainer;
