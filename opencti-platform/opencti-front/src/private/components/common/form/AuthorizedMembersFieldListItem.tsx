// FDS-WORKAROUND #44: kept on MUI Select. `tests_e2e/dashboardRestriction`
// became INTERMITTENT once this field was converted — same commit red on one
// run and green on the re-run, failing on
// `getByRole('listbox', { name: 'Access right' }).getByText('can view')` with
// "visible, enabled and stable" never satisfied. Diagnosed at the pointer on
// the real access-restriction dialog and NOT reproduced: the listbox opens
// correctly named, the option measures 97x32 with `pointer-events: auto`, and
// `elementFromPoint` at its centre returns the option itself. Cause unidentified,
// so this is a revert rather than a fix — an access-rights control does not get
// carried forward on a green re-run. Note the dialog stacks THREE Radix Selects
// (this field plus one per member row) beside a MUI Autocomplete, which is the
// obvious place to look next — see fds-migration/LIBRARY-FEEDBACK.md #44
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import { Field } from 'formik';
import MenuItem from '@mui/material/MenuItem';
import { Delete, InfoOutlined } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import { Tooltip } from '@mui/material';
import React from 'react';
import { isGenericOption } from '@components/common/form/AuthorizedMembersField';
import SelectField from '../../../../components/fields/SelectField';
import ItemIcon from '../../../../components/ItemIcon';
import useAuth from '../../../../utils/hooks/useAuth';
import { useFormatter } from '../../../../components/i18n';
import { AccessRight, AuthorizedMemberOption } from '../../../../utils/authorizedMembers';

// Common style applied in JSX.
const smallText = {
  opacity: 0.6,
  fontStyle: 'italic',
};

interface AuthorizedMembersFieldListItemProps {
  authorizedMember: AuthorizedMemberOption;
  name: string;
  accessRights: { label: string; value: string }[];
  onRemove?: () => void;
  onChange?: (val: AccessRight) => void;
  ownerId?: string;
  disabled?: boolean;
}

const AuthorizedMembersFieldListItem = ({
  authorizedMember,
  name,
  accessRights,
  onRemove,
  onChange,
  ownerId,
  disabled,
}: AuthorizedMembersFieldListItemProps) => {
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  // Used for artificial rows for ALL and CREATOR if they have
  // no access.
  const noAccess = { label: t_i18n('no access'), value: 'none' };
  const groupsLabel = (authorizedMember.groupsRestriction ?? []).map((n) => n.label);

  // Construct the list of available access levels based on
  // if generic option or not.
  const getAccessList = (memberId: string) => {
    return isGenericOption(memberId)
      ? [noAccess, ...accessRights]
      : accessRights;
  };

  return (
    <ListItem
      dense={true}
      divider={false}
      sx={{
        p: 0,
        height: '40px',
        '.MuiInputBase-root': {
          mt: '8px',
        },
      }}
    >
      <ListItemIcon>
        <ItemIcon type={authorizedMember.type} />
      </ListItemIcon>

      <ListItemText
        primary={(
          <>
            {authorizedMember.label && authorizedMember.type ? (
              authorizedMember.label
            ) : (
              <span style={smallText}>
                {t_i18n('Deleted or restricted member')}
              </span>
            )}
            {authorizedMember.value === me.id && (
              <span style={smallText}>
                {' '}({t_i18n('you')})
              </span>
            )}
            {authorizedMember.value === ownerId && (
              <span style={smallText}>
                {' '}({t_i18n('Creator')})
              </span>
            )}
            {authorizedMember.groupsRestriction && authorizedMember.groupsRestriction.length > 0 && (
              <>
                <span style={smallText}>
                  {' '}({t_i18n('Groups restriction')})
                </span>
                <Tooltip title={`Groups restriction: ${groupsLabel}`}>
                  <IconButton size="small" color="primary">
                    <InfoOutlined fontSize="small" />
                  </IconButton>
                </Tooltip>
              </>
            )}
          </>
        )}
      />

      <Field
        component={SelectField}
        name={name}
        sx={{ m: 1, minWidth: 120 }}
        inputProps={{ 'aria-label': 'Without label' }}
        disabled={
          disabled || authorizedMember.value === me.id || !authorizedMember.label
        }
        size="small"
        disableUnderline
        onChange={(_: string, val: AccessRight) => onChange?.(val)}
      >
        {getAccessList(authorizedMember.value).map((accessRight) => (
          <MenuItem
            value={accessRight.value}
            key={accessRight.value}
          >
            {accessRight.label}
          </MenuItem>
        ))}
      </Field>

      {(
        authorizedMember.value !== me.id
        && !isGenericOption(authorizedMember.value)
      )
        ? (
            <IconButton
              color="primary"
              aria-label={t_i18n('Delete')}
              onClick={() => onRemove?.()}
              disabled={disabled}
            >
              <Delete fontSize="small" />
            </IconButton>
          )
        : <div style={{ width: 36 }}></div>
      }
    </ListItem>
  );
};

export default AuthorizedMembersFieldListItem;
