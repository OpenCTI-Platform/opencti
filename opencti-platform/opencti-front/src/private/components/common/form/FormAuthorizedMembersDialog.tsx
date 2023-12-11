import ToggleButton from '@mui/material/ToggleButton';
import { LockPersonOutlined } from '@mui/icons-material';
import React, { useState } from 'react';
import FormAuthorizedMembers, {
  FormAuthorizedMembersInputs,
} from '@components/common/form/FormAuthorizedMembers';
import { FormikHelpers } from 'formik/dist/types';
import { useMutation } from 'react-relay';
import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import { useFormatter } from '../../../../components/i18n';
import {
  AuthorizedMemberOption,
  Creator,
} from '../../../../utils/authorizedMembers';
import { handleErrorInForm } from '../../../../relay/environment';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

interface FormAuthorizedMembersDialogProps {
  id: string;
  mutation: GraphQLTaggedNode;
  authorizedMembers?: AuthorizedMemberOption[];
  owner?: Creator;
}

const FormAuthorizedMembersDialog = ({
  id,
  mutation,
  authorizedMembers,
  owner,
}: FormAuthorizedMembersDialogProps) => {
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const isEnterpriseEdition = useEnterpriseEdition();
  const [commit] = useMutation(mutation);
  const onSubmit = (
    values: FormAuthorizedMembersInputs,
    {
      setSubmitting,
      resetForm,
      setErrors,
    }: FormikHelpers<FormAuthorizedMembersInputs>,
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
      <EETooltip title={t('Manage access restriction')}>
        <ToggleButton
          onClick={() => isEnterpriseEdition && setOpen(true)}
          value="manage-access"
          size="small"
          style={{ marginRight: 3 }}
        >
          <LockPersonOutlined
            fontSize="small"
            color={isEnterpriseEdition ? 'primary' : 'disabled'}
          />
        </ToggleButton>
      </EETooltip>
      <FormAuthorizedMembers
        existingAccessRules={authorizedMembers ?? null}
        open={open}
        handleClose={() => setOpen(false)}
        onSubmit={onSubmit}
        owner={owner}
        canDeactivate
      />
    </>
  );
};

export default FormAuthorizedMembersDialog;
