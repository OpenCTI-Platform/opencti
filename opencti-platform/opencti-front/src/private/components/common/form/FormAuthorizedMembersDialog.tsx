import ToggleButton from '@mui/material/ToggleButton';
import { LockPersonOutlined } from '@mui/icons-material';
import React, { useState } from 'react';
import FormAuthorizedMembers, { FormAuthorizedMembersInputs } from '@components/common/form/FormAuthorizedMembers';
import { FormikHelpers } from 'formik/dist/types';
import { useMutation } from 'react-relay';
import { GraphQLTaggedNode } from 'relay-runtime/lib/query/RelayModernGraphQLTag';
import EETooltip from '@components/common/entreprise_edition/EETooltip';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import { AuthorizedMemberOption } from '../../../../utils/authorizedMembers';
import { handleErrorInForm } from '../../../../relay/environment';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';
import { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  buttonEE: {
    borderColor: theme.palette.ee.main,
  },
}));

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
  const classes = useStyles();
  const { t } = useFormatter();
  const [open, setOpen] = useState(false);
  const isEnterpriseEdition = useEnterpriseEdition();

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
      <EETooltip title={t('Manage access restriction')}>
        <ToggleButton
          onClick={() => isEnterpriseEdition && setOpen(true)}
          value="manage-access"
          size="small"
          style={{ marginRight: 3 }}
          classes={{ root: isEnterpriseEdition ? undefined : classes.buttonEE }}
        >
          <LockPersonOutlined fontSize="small" color={isEnterpriseEdition ? 'warning' : 'ee'} />
        </ToggleButton>
      </EETooltip>
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
