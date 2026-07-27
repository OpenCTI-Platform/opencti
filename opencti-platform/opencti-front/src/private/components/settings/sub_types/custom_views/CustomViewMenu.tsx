import React, { UIEvent, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { useNavigate } from 'react-router-dom';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import MoreVert from '@mui/icons-material/MoreVert';
import IconButton from '@common/button/IconButton';
import { useFormatter } from '../../../../../components/i18n';
import useDeletion from '../../../../../utils/hooks/useDeletion';
import CustomViewDuplicationDialog from './CustomViewDuplicationDialog';
import type { CustomViewMenu_customView$key } from './__generated__/CustomViewMenu_customView.graphql';
import CustomViewDeletionDialog from './CustomViewDeletionDialog';
import useCustomViewEdit from './useCustomViewEdit';
import CustomViewReplaceDefaultDialog from './CustomViewReplaceDefaultDialog';
import { fetchQuery, handleError } from 'src/relay/environment';

const menuFragment = graphql`
  fragment CustomViewMenu_customView on CustomView {
    id
    name
    default
    targetEntityType
    ...CustomViewDuplicationDialog_Fragment
  }
`;

const customViewCurrentDefaultQuery = graphql`
  query CustomViewMenuCurrentDefaultQuery($entityType: String!) {
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

interface CustomViewMenuProps {
  data: CustomViewMenu_customView$key;
}

const noop = () => {};

const useDuplicate = (onDuplicate = noop) => {
  const [displayDuplicate, setDisplayDuplicate] = useState(false);
  const handleCloseDuplicate = () => setDisplayDuplicate(false);
  const [duplicating, setDuplicating] = useState(false);
  const handleDuplication = () => {
    onDuplicate();
    setDisplayDuplicate(true);
  };

  return {
    displayDuplicate,
    setDisplayDuplicate,
    handleCloseDuplicate,
    duplicating,
    setDuplicating,
    handleDuplication,
  };
};

const CustomViewMenu = ({ data }: CustomViewMenuProps) => {
  const customView = useFragment(menuFragment, data);
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const [replaceDefaultDialogOpen, setReplaceDefaultDialogOpen] = useState(false);
  const [currentDefaultName, setCurrentDefaultName] = useState<string | undefined>(undefined);
  const open = Boolean(anchorEl);
  const navigate = useNavigate();

  const [commitCustomViewMutation] = useCustomViewEdit();

  const handleClick = (event: React.MouseEvent<HTMLElement, MouseEvent>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };
  const handleDeleted = () => {
    navigate(`/dashboard/settings/customization/entity_types/${customView.targetEntityType}/custom-views`);
  };

  const doSetDefault = () => {
    commitCustomViewMutation({
      variables: {
        id: customView.id,
        input: [{ key: 'default', value: [true] }],
      },
    });
  };

  const onSetAsDefault = () => {
    setAnchorEl(null);
    fetchQuery(customViewCurrentDefaultQuery, { entityType: customView.targetEntityType })
      .toPromise()
      .then((result: unknown) => {
        const queryData = result as { customViews?: { edges: { node: { id: string; name: string; default: boolean } }[] } };
        const existingDefault = queryData.customViews?.edges
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

  const onRemoveDefault = () => {
    setAnchorEl(null);
    commitCustomViewMutation({
      variables: {
        id: customView.id,
        input: [{ key: 'default', value: [false] }],
      },
    });
  };

  const {
    displayDuplicate,
    duplicating,
    setDuplicating,
    handleDuplication,
    handleCloseDuplicate,
  } = useDuplicate(handleClose);
  const deletion = useDeletion({ handleClose });
  const handleOpenDelete = (e: UIEvent) => {
    setAnchorEl(null);
    deletion.handleOpenDelete(e);
  };
  return (
    <div>
      <IconButton
        aria-label={t_i18n('Popover of custom view actions')}
        value="popover"
        color="secondary"
        id="custom-view-menu-button"
        aria-controls={open ? 'custom-view-menu' : undefined}
        aria-haspopup="true"
        aria-expanded={open ? 'true' : undefined}
        onClick={handleClick}
        variant="secondary"
        size="default"
      >
        <MoreVert color="primary" fontSize="small" />
      </IconButton>
      <Menu
        id="custom-view-kebab-menu"
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        slotProps={{
          list: {
            'aria-labelledby': 'workspace-kebab-button',
          },
        }}
      >
        <MenuItem onClick={handleDuplication}>{t_i18n('Duplicate the custom view')}</MenuItem>
        {customView.default
          ? <MenuItem onClick={onRemoveDefault}>{t_i18n('Remove default')}</MenuItem>
          : <MenuItem onClick={onSetAsDefault}>{t_i18n('Set as default')}</MenuItem>
        }
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <CustomViewDeletionDialog
        id={customView.id}
        deletion={deletion}
        onDeleted={handleDeleted}
      />
      <CustomViewDuplicationDialog
        data={customView}
        displayDuplicate={displayDuplicate}
        handleCloseDuplicate={handleCloseDuplicate}
        duplicating={duplicating}
        setDuplicating={setDuplicating}
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

export default CustomViewMenu;
