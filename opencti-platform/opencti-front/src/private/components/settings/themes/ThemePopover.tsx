import { MoreVert } from '@mui/icons-material';
import { Menu, MenuItem } from '@mui/material';
import { IconButton } from '@filigran/design-system';
import React, { FunctionComponent, useContext, useState } from 'react';
import { Disposable, graphql, RecordSourceSelectorProxy } from 'relay-runtime';
import { ThemeManagerQuery$variables } from '@components/settings/themes/__generated__/ThemeManagerQuery.graphql';
import { ThemeManager_data$data } from '@components/settings/themes/__generated__/ThemeManager_data.graphql';
import { useFormatter } from '../../../../components/i18n';
import ThemeEdition from './ThemeEdition';
import Security from '../../../../utils/Security';
import { SETTINGS_SETPARAMETERS } from '../../../../utils/hooks/useGranted';
import ThemeType from './ThemeType';
import handleExportJson from './ThemeExportHandler';
import useDeletion from '../../../../utils/hooks/useDeletion';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { deleteNode } from '../../../../utils/store';
import DeleteDialog from '../../../../components/DeleteDialog';
import { UserContext, UserContextType } from '../../../../utils/hooks/useAuth';
import { getLoginAsideType } from './theme-utils';

const deleteUserThemeMutation = graphql`
  mutation ThemePopoverUserDeletionMutation($input: [EditInput!]!) {
    meEdit(input: $input) {
      theme
    }
  }
`;

const deleteThemeMutation = graphql`
  mutation ThemePopoverDeletionMutation($id: ID!) {
    themeDelete(id:$id)
  }
`;

interface ThemePopoverProps {
  themeData: ThemeManager_data$data;
  handleRefetch: () => Disposable;
  paginationOptions: ThemeManagerQuery$variables;
  canDelete: boolean;
  defaultTheme?: {
    id: string;
    name: string;
  } | null;
}

const ThemePopover: FunctionComponent<ThemePopoverProps> = ({
  themeData,
  handleRefetch,
  paginationOptions,
  canDelete = false,
  defaultTheme,
}) => {
  const { t_i18n } = useFormatter();

  const { me } = useContext<UserContextType>(UserContext);

  const [anchorEl, setAnchorEl] = useState<(EventTarget & Element) | null>(null);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);

  const theme: ThemeType = {
    id: themeData.id,
    name: themeData.name,
    theme_background: themeData.theme_background,
    theme_paper: themeData.theme_paper,
    theme_nav: themeData.theme_nav,
    theme_primary: themeData.theme_primary,
    theme_secondary: themeData.theme_secondary,
    theme_accent: themeData.theme_accent,
    theme_logo: themeData.theme_logo,
    theme_logo_collapsed: themeData.theme_logo_collapsed,
    theme_logo_login: themeData.theme_logo_login,
    theme_text_color: themeData.theme_text_color,
    built_in: themeData.built_in,
    theme_login_aside_color: themeData.theme_login_aside_color,
    theme_login_aside_gradient_end: themeData.theme_login_aside_gradient_end,
    theme_login_aside_gradient_start: themeData.theme_login_aside_gradient_start,
    theme_login_aside_image: themeData.theme_login_aside_image,

    theme_login_aside_type: getLoginAsideType({
      theme_login_aside_color: themeData.theme_login_aside_color,
      theme_login_aside_gradient_start:
      themeData.theme_login_aside_gradient_start,
      theme_login_aside_gradient_end:
      themeData.theme_login_aside_gradient_end,
      theme_login_aside_image: themeData.theme_login_aside_image,
    }),
  };

  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('Theme') },
  });

  const [commit] = useApiMutation(
    deleteThemeMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const [commitUserResetTheme] = useApiMutation(deleteUserThemeMutation);

  const deletion = useDeletion({ handleClose: () => setAnchorEl(null) });

  const { setDeleting, handleOpenDelete, deleting } = deletion;

  const handleOpen = (event: React.UIEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };

  const handleCloseUpdate = () => {
    setDisplayUpdate(false);
  };

  const handleExport = () => {
    handleExportJson(theme);
  };

  const submitDelete = () => {
    setDeleting(true);

    const userThemeId = me?.theme;
    // reset to default if the user is currently using a theme
    // that we delete here
    if (userThemeId === themeData.id && defaultTheme) {
      commitUserResetTheme({
        variables: {
          input: [{
            key: 'theme',
            value: defaultTheme.id,
          }],
        },
      });
    }

    commit({
      variables: { id: theme.id },
      updater: (store: RecordSourceSelectorProxy) => deleteNode(
        store,
        'Pagination_themes',
        paginationOptions,
        theme.id,
      ),
      onCompleted: () => {
        setDeleting(false);
        handleRefetch();
      },
    });

    handleClose();
  };

  const isMenuOpen = Boolean(anchorEl);
  const isDeleteDisabled = themeData.built_in || !canDelete || deleting;

  return (
    <div>
      <Security
        needs={[SETTINGS_SETPARAMETERS]}
      >
        <IconButton
          variant="default"
          priority="tertiary"
          aria-label={t_i18n('Open menu')}
          onClick={handleOpen}
          aria-haspopup="true"
          data-testid={`${theme.name}-popover`}
          icon={<MoreVert />}
        />
      </Security>

      <Menu
        anchorEl={anchorEl}
        open={isMenuOpen}
        onClose={handleClose}
      >
        <Security needs={[SETTINGS_SETPARAMETERS]}>
          <MenuItem
            onClick={handleOpenUpdate}
            aria-label={theme.built_in
              ? t_i18n('View')
              : t_i18n('Update')
            }
          >
            {theme.built_in
              ? t_i18n('View')
              : t_i18n('Update')}
          </MenuItem>
        </Security>
        <Security needs={[SETTINGS_SETPARAMETERS]}>
          <MenuItem
            onClick={handleExport}
            aria-label={t_i18n('Export')}
          >
            {t_i18n('Export')}
          </MenuItem>
        </Security>
        {!theme.built_in && (
          <Security needs={[SETTINGS_SETPARAMETERS]}>
            <MenuItem
              onClick={handleOpenDelete}
              aria-label={t_i18n('Delete')}
              disabled={isDeleteDisabled}
            >
              {t_i18n('Delete')}
            </MenuItem>
          </Security>
        )}
      </Menu>
      <ThemeEdition
        theme={theme}
        open={displayUpdate}
        handleClose={handleCloseUpdate}
      />
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this theme?')}
      />
    </div>
  );
};

export default ThemePopover;
