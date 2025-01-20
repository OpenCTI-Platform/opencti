import React from 'react';
import { Box, Button } from '@mui/material';
import { graphql, useMutation } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import TextField from '../../../../components/TextField';

interface StixCoreObjectContentFilesDisseminationProps {
  fileId: string;
  fileName: string;
  onClose: () => void;
}

export const DisseminationListSendInputMutation = graphql`
    mutation StixCoreObjectContentFilesDisseminationMutation(
        $input: DisseminationListSendInput!
    ) {
        disseminationListSend(input: $input)
    }
`;

const StixCoreObjectContentFilesDissemination: React.FC<StixCoreObjectContentFilesDisseminationProps> = ({
  fileId,
  fileName,
}) => {
  const [commitMutation] = useMutation(DisseminationListSendInputMutation);

  const handleSubmit = (values: any, { setSubmitting }: any) => {
    setSubmitting(true);

    commitMutation({
      variables: {
        input: {
          email_address: values.emailAddress,
          email_object: values.emailObject,
          email_body: values.emailBody,
          email_attached_file_id: fileId,
        },
      },
      onCompleted: (response) => {
        if (response) {
          // TODO
        } else {
          // TODO
        }
        setSubmitting(false);
      },
      onError: (error) => {
        // TODO
        setSubmitting(false);
      },
    });
  };

  return (
    <Formik
      initialValues={{
        emailAddress: '',
        emailObject: '',
        emailBody: '',
      }}
      onSubmit={handleSubmit}
    >
      {({ isSubmitting, submitForm }) => (
        <Box sx={{ display: 'flex', flexDirection: 'column' }}>
          <Field
            component={TextField}
            label="Email Address"
            name="emailAddress"
            type="email"
            fullWidth
            required
          />
          <Field
            component={TextField}
            label="Object"
            name="emailObject"
            fullWidth
            required
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={TextField}
            label="Body"
            name="emailBody"
            multiline
            rows={6}
            fullWidth
            required
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={TextField}
            label="file"
            name="file"
            fullWidth
            value={fileName}
            disabled
            style={fieldSpacingContainerStyle}
          />
          <div style={{
            marginTop: 20,
            textAlign: 'right',
          }}
          >
            <Button
              onClick={submitForm}
              variant="contained"
              color="primary"
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Sending...' : 'Send Email'}
            </Button>
          </div>
        </Box>
      )}
    </Formik>
  );
};

export default StixCoreObjectContentFilesDissemination;
