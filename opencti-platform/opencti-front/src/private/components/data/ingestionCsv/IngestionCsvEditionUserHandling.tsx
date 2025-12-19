import React, { FunctionComponent, useState } from 'react';
import CreatorField from '@components/common/form/CreatorField';
import Button from '@common/button/Button';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Dialog from '@mui/material/Dialog';
import ConfidenceField from '@components/common/form/ConfidenceField';
import { Box } from '@mui/material';
import { graphql } from 'react-relay';
import { FormikConfig } from 'formik/dist/types';
import { Formik } from 'formik';
import * as Yup from 'yup';
import { IngestionCsvEditionUserHandlingQuery$data } from '@components/data/ingestionCsv/__generated__/IngestionCsvEditionUserHandlingQuery.graphql';
import Alert from '@mui/material/Alert';
import { fetchQuery } from '../../../../relay/environment';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import Transition from '../../../../components/Transition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

export const ingestionCsvEditionUserHandlingQuery = graphql`
  query IngestionCsvEditionUserHandlingQuery(
    $name: String!
  ) {
    userAlreadyExists(
      name: $name
    )
  }
`;

export const ingestionCsvEditionUserHandlingFragment = graphql`
  fragment IngestionCsvEditionUserHandlingFragment_ingestionCsv on IngestionCsv {
    id
    name
    user {
      id
      entity_type
      name
    }
  }
`;
export const ingestionCsvEditionUserHandlingPatch = graphql`
  mutation IngestionCsvEditionUserHandlingMutation($id: ID!, $input: IngestionCsvAddAutoUserInput!) {
    ingestionCsvAddAutoUser(id: $id, input: $input) {
      ...IngestionCsvEditionUserHandlingFragment_ingestionCsv
    }
  }
`;

export interface EditionCsvAddAutoUserInput {
  user_name: string;
  confidence_level: number;
}

interface IngestionCsvEditionUserHandlingProps {
  feedName: string;
  ingestionCsvDataId: string;
  onAutoUserCreated: () => void;
}
const IngestionCsvEditionUserHandling: FunctionComponent<IngestionCsvEditionUserHandlingProps> = ({ feedName, ingestionCsvDataId, onAutoUserCreated }) => {
  const { t_i18n } = useFormatter();

  const [openDialog, setOpenDialog] = useState(false);
  const [commitUpdate] = useApiMutation(ingestionCsvEditionUserHandlingPatch);
  const ingestionCsvCreationValidation = () => Yup.object().shape({
    user_name: Yup.string(),
    confidence_level: Yup.string(),
  });

  const initialValues: EditionCsvAddAutoUserInput = {
    user_name: `[F] ${feedName}`,
    confidence_level: 50,
  };

  const onSubmit: FormikConfig<EditionCsvAddAutoUserInput>['onSubmit'] = async (
    values,
    { setSubmitting, setFieldError },
  ) => {
    const existingUsers = await fetchQuery(ingestionCsvEditionUserHandlingQuery, {
      name: values.user_name,
    })
      .toPromise();

    if ((existingUsers as IngestionCsvEditionUserHandlingQuery$data)?.userAlreadyExists) {
      setSubmitting(false);
      setFieldError('user_name', t_i18n('This service account already exists. Change the feed\'s name to change the automatically created service account name'));
      return;
    }

    // send data to backend
    commitUpdate({
      variables: {
        id: ingestionCsvDataId,
        input: {
          user_name: values.user_name,
          confidence_level: values.confidence_level,
        },
      },
      onCompleted: () => {
        onAutoUserCreated();
        setSubmitting(false);
        setOpenDialog(false);
      },
    });
  };

  return (

    <>
      <Alert
        severity="warning"
        variant="outlined"
        sx={{ padding: '0px 10px 0px 10px', marginTop: '20px' }}
      >
        <Box>
          {t_i18n('You have set System as a creator. Create a service account for this feed to ensure traceability of your data')}
        </Box>
        <Button onClick={() => setOpenDialog(true)}>{ t_i18n('Create a service account for this feed')}</Button>

      </Alert>

      <Formik<EditionCsvAddAutoUserInput>
        initialValues={initialValues}
        validationSchema={ingestionCsvCreationValidation}
        onSubmit={onSubmit}
      >
        {({ submitForm, resetForm }) => (

          <Box sx={{ paddingRight: '50px' }}>
            <Dialog
              sx={{ paddingRight: '150px' }}
              open={openDialog}
              fullWidth={true}
              keepMounted={true}
              slots={{ transition: Transition }}
              onClose={() => {
                setOpenDialog(false);
              }}
            >
              <DialogTitle>
                {t_i18n('Create an automatic user')}
              </DialogTitle>
              <DialogContent>
                <Box sx={{ margin: '0 70px 0' }}>
                  <CreatorField
                    name="user_name"
                    label={t_i18n('Service account responsible for data creation')}
                    containerStyle={fieldSpacingContainerStyle}
                    showConfidence
                    disabled={true}
                  />
                </Box>
                <Box sx={{ margin: '20px 70px 0' }}>
                  <ConfidenceField
                    name="confidence_level"
                    entityType="User"
                    containerStyle={fieldSpacingContainerStyle}
                    showAlert={false}
                  />
                </Box>
              </DialogContent>
              <DialogActions>
                <Button
                  variant="secondary"
                  onClick={() => {
                    setOpenDialog(false); resetForm();
                  }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button onClick={() => {
                  submitForm();
                }}
                >
                  {t_i18n('Confirm')}
                </Button>
              </DialogActions>
            </Dialog>
          </Box>

        )}
      </Formik>
    </>
  );
};

export default IngestionCsvEditionUserHandling;
