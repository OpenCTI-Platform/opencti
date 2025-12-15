import React, { FunctionComponent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Avatar, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, Tooltip } from '@mui/material';
import { DeleteOutlined, StorageOutlined } from '@mui/icons-material';
import { Link } from 'react-router-dom';
import { LinkVariantPlus, LinkVariantRemove, Merge, VectorRadius } from 'mdi-material-ui';
import { v4 as uuid } from 'uuid';
import { deepOrange, green, indigo, lightGreen, orange, pink, red, teal, yellow } from '@mui/material/colors';
import Button from '@common/button/Button';
import { useTheme } from '@mui/styles';
import { UserHistoryTab_user$key } from './__generated__/UserHistoryTab_user.graphql';
import DataTable from '../../../../components/dataGrid/DataTable';
import { emptyFilterGroup, GqlFilterGroup } from '../../../../utils/filters/filtersUtils';
import { userHistoryLineFragment } from './UserHistoryLine';
import { userHistoryLinesFragment, userHistoryLinesQuery } from './UserHistoryLines';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { UserHistoryLinesQuery, UserHistoryLinesQuery$variables } from './__generated__/UserHistoryLinesQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { UsePreloadedPaginationFragment } from '../../../../utils/hooks/usePreloadedPaginationFragment';
import { UserHistoryLines_data$data } from './__generated__/UserHistoryLines_data.graphql';
import useGranted, { KNOWLEDGE, SETTINGS_SECURITYACTIVITY } from '../../../../utils/hooks/useGranted';
import { DataTableProps } from '../../../../components/dataGrid/dataTableTypes';
import { useFormatter } from '../../../../components/i18n';
import ItemIcon from '../../../../components/ItemIcon';
import type { Theme } from '../../../../components/Theme';
import { UserHistoryLine_node$data } from './__generated__/UserHistoryLine_node.graphql';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const LOCAL_STORAGE_KEY = 'audits';

const userFragment = graphql`
  fragment UserHistoryTab_user on User {
    id
  }
`;

interface UserHistoryTabProps {
  data: UserHistoryTab_user$key;
}

const UserHistoryTab: FunctionComponent<UserHistoryTabProps> = ({
  data: userData,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const user = useFragment(userFragment, userData);
  const [message, setMessage] = useState<string>('-');
  const [open, setOpen] = useState<boolean>(false);
  const handleOpen = () => {
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
    setMessage('-');
  };
  const dataColumns: DataTableProps['dataColumns'] = {
    event_scope: {},
    timestamp: {},
  };
  const initialValues = {
    searchTerm: '',
    sortBy: 'timestamp',
    orderAsc: true,
    openExports: false,
    filters: emptyFilterGroup,
  };
  const { helpers, paginationOptions } = usePaginationLocalStorage<UserHistoryLinesQuery$variables>(
    LOCAL_STORAGE_KEY,
    initialValues,
  );
  const isGrantedToAudit = useGranted([SETTINGS_SECURITYACTIVITY]);
  const isGrantedToKnowledge = useGranted([KNOWLEDGE]);
  let historyTypes = ['History'];
  if (isGrantedToAudit && !isGrantedToKnowledge) {
    historyTypes = ['Activity'];
  } else if (isGrantedToAudit && isGrantedToKnowledge) {
    historyTypes = ['History', 'Activity'];
  }
  const queryPaginationOptions = {
    ...paginationOptions,
    types: historyTypes,
    filters: {
      mode: 'or',
      filterGroups: [],
      filters: [
        { key: ['user_id'], values: [user.id], operator: 'wildcard', mode: 'or' },
        { key: ['context_data.id'], values: [user.id], operator: 'wildcard', mode: 'or' },
      ],
    } as GqlFilterGroup,
    first: 25,
  } as unknown as UserHistoryLinesQuery$variables;
  const queryRef = useQueryLoading<UserHistoryLinesQuery>(
    userHistoryLinesQuery,
    queryPaginationOptions,
  );
  const preloadedPaginationProps = {
    linesQuery: userHistoryLinesQuery,
    linesFragment: userHistoryLinesFragment,
    queryRef,
    nodePath: ['audits', 'pageInfo', 'globalCount'],
    setNumberOfElements: helpers.handleSetNumberOfElements,
  } as UsePreloadedPaginationFragment<UserHistoryLinesQuery>;

  // Entities and relationships redirection filters
  const technicalCreatorFilters = JSON.stringify({
    mode: 'and',
    filterGroups: [],
    filters: [
      {
        key: 'creator_id',
        values: [
          user.id,
        ],
        operator: 'eq',
        mode: 'or',
        id: uuid(), // because filters in the URL
      },
    ],
  });

  const renderIcon = (eventScope: string | null | undefined, eventMessage: string | undefined, commit: string | null | undefined) => {
    setMessage(eventMessage ?? '-');
    if (eventScope === 'create') {
      return (
        <Avatar
          sx={{
            width: 25,
            height: 25,
            backgroundColor: 'transparent',
            border: `1px solid ${pink[500]}`,
            color: theme.palette.text?.primary,
            cursor: commit ? 'pointer' : 'auto',
          }}
          onClick={() => commit && handleOpen()}
        >
          {/* <ItemIcon type={eventScope} color="inherit" size="small" /> */}
          <ItemIcon type={eventScope} size="small" />
        </Avatar>
      );
    }
    if (eventScope === 'merge') {
      return (
        <Avatar
          sx={{
            width: 25,
            height: 25,
            backgroundColor: 'transparent',
            border: `1px solid ${teal[500]}`,
            color: theme.palette.text?.primary,
            cursor: commit ? 'pointer' : 'auto',
          }}
          onClick={() => commit && handleOpen()}
        >
          <Merge fontSize="small" />
        </Avatar>
      );
    }
    if (
      eventScope === 'update'
      && (eventMessage?.includes('replaces') || eventMessage?.includes('updates'))
    ) {
      return (
        <Avatar
          sx={{
            width: 25,
            height: 25,
            backgroundColor: 'transparent',
            border: `1px solid ${green[500]}`,
            color: theme.palette.text?.primary,
            cursor: commit ? 'pointer' : 'auto',
          }}
          onClick={() => commit && handleOpen()}
        >
          {/* <ItemIcon type={eventScope} color="inherit" size="small" /> */}
          <ItemIcon type={eventScope} size="small" />
        </Avatar>
      );
    }
    if (eventScope === 'update' && eventMessage?.includes('changes')) {
      return (
        <Avatar
          sx={{
            width: 25,
            height: 25,
            backgroundColor: 'transparent',
            border: `1px solid ${green[500]}`,
            color: theme.palette.text?.primary,
            cursor: commit ? 'pointer' : 'auto',
          }}
          onClick={() => commit && handleOpen()}
        >
          {/* <ItemIcon type={eventScope} color="inherit" size="small" /> */}
          <ItemIcon type={eventScope} size="small" />
        </Avatar>
      );
    }
    if (eventScope === 'update' && eventMessage?.includes('adds')) {
      return (
        <Avatar
          sx={{
            width: 25,
            height: 25,
            backgroundColor: 'transparent',
            border: `1px solid ${indigo[500]}`,
            color: theme.palette.text?.primary,
            cursor: commit ? 'pointer' : 'auto',
          }}
          onClick={() => commit && handleOpen()}
        >
          <LinkVariantPlus fontSize="small" />
        </Avatar>
      );
    }
    if (eventScope === 'update' && eventMessage?.includes('removes')) {
      return (
        <Avatar
          sx={{
            width: 25,
            height: 25,
            backgroundColor: 'transparent',
            border: `1px solid ${deepOrange[500]}`,
            color: theme.palette.text?.primary,
            cursor: commit ? 'pointer' : 'auto',
          }}
          onClick={() => commit && handleOpen()}
        >
          <LinkVariantRemove fontSize="small" />
        </Avatar>
      );
    }
    if (eventScope === 'delete') {
      return (
        <Avatar
          sx={{
            width: 25,
            height: 25,
            backgroundColor: 'transparent',
            border: `1px solid ${red[500]}`,
            color: theme.palette.text?.primary,
          }}
        >
          <DeleteOutlined fontSize="small" />
        </Avatar>
      );
    }
    if (eventScope === 'read') {
      return (
        <Avatar
          sx={{
            width: 25,
            height: 25,
            backgroundColor: 'transparent',
            border: `1px solid ${lightGreen[500]}`,
            color: theme.palette.text?.primary,
            cursor: commit ? 'pointer' : 'auto',
          }}
        >
          {/* <ItemIcon type={eventScope} color="inherit" size="small" /> */}
          <ItemIcon type={eventScope} size="small" />
        </Avatar>
      );
    }
    if (eventScope === 'download') {
      return (
        <Avatar
          sx={{
            width: 25,
            height: 25,
            backgroundColor: 'transparent',
            border: `1px solid ${orange[500]}`,
            color: theme.palette.text?.primary,
            cursor: commit ? 'pointer' : 'auto',
          }}
        >
          {/* <ItemIcon type={eventScope} color="inherit" size="small" /> */}
          <ItemIcon type={eventScope} size="small" />
        </Avatar>
      );
    }
    return (
      <Avatar
        sx={{
          width: 25,
          height: 25,
          backgroundColor: 'transparent',
          border: `1px solid ${yellow[500]}`,
          color: theme.palette.text?.primary,
        }}
        onClick={() => commit && handleOpen()}
      >
        {/* <ItemIcon type={eventScope} color="inherit" size="small" /> */}
        <ItemIcon type={eventScope} size="small" />
      </Avatar>
    );
  };

  return (
    <>
      {queryRef && (
        <DataTable
          dataColumns={dataColumns}
          resolvePath={(data: UserHistoryLines_data$data) => data.audits?.edges?.map((n) => n?.node)}
          storageKey={LOCAL_STORAGE_KEY}
          initialValues={initialValues}
          lineFragment={userHistoryLineFragment}
          preloadedPaginationProps={preloadedPaginationProps}
          disableNavigation
          disableLineSelection
          removeSelectAll
          icon={(data: UserHistoryLine_node$data) => renderIcon(data.event_scope, data.context_data?.message, data.context_data?.commit)}
          additionalHeaderButtons={[
            <Tooltip title={t_i18n('View all entities created by user')} key="entities">
              <IconButton
                component={Link}
                to={`/dashboard/search/knowledge/?filters=${encodeURIComponent(technicalCreatorFilters)}`}
                color="primary"
              >
                <StorageOutlined fontSize="small" />
              </IconButton>
            </Tooltip>,
            <Tooltip title={t_i18n('View all relationships created by user')} key="relations">
              <IconButton
                component={Link}
                to={`/dashboard/data/relationships/?filters=${encodeURIComponent(technicalCreatorFilters)}`}
                color="primary"
              >
                <VectorRadius fontSize="small" />
              </IconButton>
            </Tooltip>,
          ]}
        />
      )}
      <Dialog
        open={open}
        slotProps={{ paper: { elevation: 1 } }}
        onClose={handleClose}
        fullWidth={true}
      >
        <DialogTitle>{t_i18n('Commit message')}</DialogTitle>
        <DialogContent>
          <MarkdownDisplay
            content={message}
            remarkGfmPlugin={true}
            commonmark={true}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={handleClose}>
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default UserHistoryTab;
