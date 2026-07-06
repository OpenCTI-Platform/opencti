import { UIEvent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import MoreVert from '@mui/icons-material/MoreVert';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../components/i18n';
import stopEvent from '../../../../../utils/domEvent';
import { CustomViewPopover_customView$key } from './__generated__/CustomViewPopover_customView.graphql';
import CustomViewDeletionDialog from './CustomViewDeletionDialog';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import useCustomViewEdit from './useCustomViewEdit';
import CustomViewReplaceDefaultDialog from './CustomViewReplaceDefaultDialog';
import { fetchQuery, handleError } from 'src/relay/environment';
import { customViewsLinesQuery } from './CustomViewsSettingsDataTable';
import type { CustomViewsSettingsDataTablePaginationQuery$variables } from './__generated__/CustomViewsSettingsDataTablePaginationQuery.graphql';

const customViewPopoverFragment = graphql`
  fragment CustomViewPopover_customView on CustomView {
    id
    name
    enabled
    default
    targetEntityType
  }
`;

const customViewCurrentDefaultQuery = graphql`
  query CustomViewPopoverCurrentDefaultQuery($entityType: String!) {
    customViews(entityType: $entityType, first: 5, orderBy: default, orderMode: desc) {
      edges {
        node {
          id
          name
          default
        }
      }
    }
  }
`;

interface CustomViewPopoverProps {
  data: CustomViewPopover_customView$key;
  paginationOptions: CustomViewsSettingsDataTablePaginationQuery$variables;
}

const CustomViewPopover = ({ data, paginationOptions }: CustomViewPopoverProps) => {
  const { t_i18n } = useFormatter();
  const customView = useFragment(customViewPopoverFragment, data);

  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [replaceDefaultDialogOpen, setReplaceDefaultDialogOpen] = useState(false);
  const [currentDefaultName, setCurrentDefaultName] = useState<string | undefined>(undefined);

  const handleOpen = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(event.currentTarget);
  };
  const handleClose = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(null);
  };

  const deletion = useDeletion({});

  const handleOpenDelete = (event: UIEvent) => {
    deletion.handleOpenDelete(event);
    setAnchorEl(null);
  };

  const [commitCustomViewMutation] = useCustomViewEdit();

  const handleToggleEnabled = (event: UIEvent) => {
    stopEvent(event);
    commitCustomViewMutation({
      variables: {
        id: customView.id,
        input: [{ key: 'enabled', value: [!customView.enabled] }],
      },
    });
    setAnchorEl(null);
  };

  const doSetDefault = () => {
    commitCustomViewMutation({
      variables: {
        id: customView.id,
        input: [{ key: 'default', value: [true] }],
      },
      onCompleted: () => {
        fetchQuery(customViewsLinesQuery, paginationOptions).toPromise().catch((err) => handleError(err));
      },
    });
  };

  const onSetAsDefault = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(null);
    fetchQuery(customViewCurrentDefaultQuery, { entityType: customView.targetEntityType })
      .toPromise()
      .then((result: unknown) => {
        const data = result as { customViews?: { edges: { node: { id: string; name: string; default: boolean } }[] } };
        const existingDefault = data.customViews?.edges
          .map((e) => e.node)
          .find((n) => n.default && n.id !== customView.id);
        if (existingDefault) {
          setCurrentDefaultName(existingDefault.name);
          setReplaceDefaultDialogOpen(true);
        } else {
          doSetDefault();
        }
      })
      .catch((err) => handleError(err));
  };

  const onRemoveDefault = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(null);
    commitCustomViewMutation({
      variables: {
        id: customView.id,
        input: [{ key: 'default', value: [false] }],
      },
      onCompleted: () => {
        fetchQuery(customViewsLinesQuery, paginationOptions).toPromise().catch((err) => handleError(err));
      },
    });
  };

  return (
    <div>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        size="small"
        color="primary"
        aria-label={t_i18n('Custom view popover of actions')}
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose} aria-label="Custom view menu">
        <MenuItem onClick={handleToggleEnabled}>{customView.enabled ? t_i18n('Disable') : t_i18n('Enable')}</MenuItem>
        {customView.default
          ? <MenuItem onClick={onRemoveDefault}>{t_i18n('Remove default')}</MenuItem>
          : <MenuItem onClick={onSetAsDefault}>{t_i18n('Set as default')}</MenuItem>
        }
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <CustomViewDeletionDialog
        id={customView.id}
        deletion={deletion}
        paginationOptions={paginationOptions}
      />
      <CustomViewReplaceDefaultDialog
        open={replaceDefaultDialogOpen}
        onClose={() => setReplaceDefaultDialogOpen(false)}
        onConfirm={() => {
          setReplaceDefaultDialogOpen(false);
          doSetDefault();
        }}
        currentDefaultName={currentDefaultName ?? ''}
      />
    </div>
  );
};

export default CustomViewPopover;
