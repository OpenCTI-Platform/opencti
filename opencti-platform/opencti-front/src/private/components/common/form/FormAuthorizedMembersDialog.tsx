import ToggleButton from '@mui/material/ToggleButton';
import { LockPersonOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import React, { useState } from 'react';
import FormAuthorizedMembers, { FormAuthorizedMembersInputs } from '@components/common/form/FormAuthorizedMembers';
import { FormikHelpers } from 'formik/dist/types';
import { useMutation } from 'react-relay';
import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import { useFormatter } from '../../../../components/i18n';
import { AuthorizedMemberOption } from '../../../../utils/authorizedMembers';
import { handleErrorInForm } from '../../../../relay/environment';

interface FormAuthorizedMembersDialogProps {
  id: string
  mutation: GraphQLTaggedNode
  authorizedMembers?: AuthorizedMemberOption[]
  ownerId?: string
}

const FormAuthorizedMembersDialog = ({
  id,
  mutation,
  authorizedMembers,
  ownerId,
}: FormAuthorizedMembersDialogProps) => {
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);

  const [commit] = useMutation(mutation);

  const onSubmit = (
    values: FormAuthorizedMembersInputs,
    { setSubmitting, resetForm, setErrors }: FormikHelpers<FormAuthorizedMembersInputs>,
  ) => {
    commit({
      variables: {
        id,
        input: !values.authorizedMembers
          ? null
          : values.authorizedMembers
            .filter((v) => v.accessRight !== 'none')
            .map((member) => ({
              id: member.value,
              access_right: member.accessRight,
            })),
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        setOpen(false);
      },
      onError: (error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

  return (
    <>
      <Tooltip title={t('Manage access')}>
        <ToggleButton
          onClick={() => setOpen(true)}
          value="manage-access"
          size="small"
          style={{ marginRight: 3 }}
        >
          <LockPersonOutlined fontSize="small" color="warning" />
        </ToggleButton>
      </Tooltip>
      <FormAuthorizedMembers
        existingAccessRules={authorizedMembers ?? null}
        open={open}
        handleClose={() => setOpen(false)}
        onSubmit={onSubmit}
        ownerId={ownerId}
        canDeactivate
      />
    </>
  );
};

export default FormAuthorizedMembersDialog;
