import { FunctionComponent, UIEvent, useMemo, useState } from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import DialogActions from '@mui/material/DialogActions';
import TextField from '@mui/material/TextField';
import { useFormatter } from '../../../../../components/i18n';
import { handleError, MESSAGING$ } from '../../../../../relay/environment';
import stopEvent from '../../../../../utils/domEvent';
import type { CustomViewDuplicationDialog_Fragment$data, CustomViewDuplicationDialog_Fragment$key } from './__generated__/CustomViewDuplicationDialog_Fragment.graphql';
import useCustomViewDuplicate from './useCustomViewDuplicate';

const customViewDuplicationFragment = graphql`
  fragment CustomViewDuplicationDialog_Fragment on CustomView {
    name
    description
    manifest
    targetEntityType
  }
`;

interface CustomViewDuplicationDialogProps {
  data: CustomViewDuplicationDialog_Fragment$key;
  displayDuplicate: boolean;
  duplicating: boolean;
  handleCloseDuplicate: () => void;
  setDuplicating: (value: boolean) => void;
}

const CustomViewDuplicationDialog: FunctionComponent<
  CustomViewDuplicationDialogProps
> = ({
  data,
  duplicating,
  setDuplicating,
  displayDuplicate,
  handleCloseDuplicate,
}) => {
  const { t_i18n } = useFormatter();
  const customView = useFragment(customViewDuplicationFragment, data);

  const duplicatedCustomViewInitialName = useMemo(
    () => `${customView.name} - ${t_i18n('copy')}`,
    [t_i18n, customView.name],
  );
  const [newName, setNewName] = useState(duplicatedCustomViewInitialName);
  const [commitDuplicateCustomView] = useCustomViewDuplicate();
  const submitDashboardDuplication = (
    e: UIEvent,
    sourceCustomView: CustomViewDuplicationDialog_Fragment$data,
  ) => {
    stopEvent(e);
    commitDuplicateCustomView({
      variables: {
        input: {
          name: sourceCustomView.name,
          description: sourceCustomView.description,
          manifest: sourceCustomView.manifest,
          targetEntityType: sourceCustomView.targetEntityType,
        },
      },
      onError: (error) => {
        handleError(error);
      },
      onCompleted: (result) => {
        handleCloseDuplicate();
        MESSAGING$.notifySuccess(
          <span>
            {t_i18n('The custom view has been duplicated. You can manage it')}{' '}
            <Link
              to={`/dashboard/settings/customization/entity_types/${result.customViewDuplicate?.targetEntityType}/custom-views/${result.customViewDuplicate?.id}`}
            >
              {t_i18n('here')}
            </Link>
            .
          </span>,
        );
      },
    });
  };

  const handleSubmitDuplicate = (e: UIEvent, submittedNewName: string) => {
    setDuplicating(true);
    submitDashboardDuplication(e, { ...customView, name: submittedNewName });
  };

  return (
    <Dialog
      open={displayDuplicate}
      onClose={handleCloseDuplicate}
      fullWidth={true}
      title={t_i18n('Duplicate the custom view')}
    >
      <TextField
        error={!newName}
        autoFocus
        margin="dense"
        id="duplicated_dashboard_name"
        label={t_i18n('New name')}
        type="text"
        fullWidth
        variant="standard"
        helperText={!newName ? `${t_i18n('This field is required')}` : ''}
        defaultValue={newName}
        onChange={(event) => {
          event.preventDefault();
          setNewName(event.target.value);
        }}
      />
      <DialogActions>
        <Button variant="secondary" onClick={() => handleCloseDuplicate()}>{t_i18n('Cancel')}</Button>
        <Button
          onClick={(e) => handleSubmitDuplicate(e, newName)}
          disabled={duplicating || !newName}
        >
          {t_i18n('Duplicate')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default CustomViewDuplicationDialog;
