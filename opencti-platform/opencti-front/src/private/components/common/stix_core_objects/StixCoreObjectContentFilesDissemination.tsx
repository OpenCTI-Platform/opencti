import React from 'react';
import { Box, Button, TextField, Typography } from '@mui/material';
import { graphql, useMutation } from 'react-relay';
import { Field, Form, Formik } from 'formik';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

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
          console.log('Email sent successfully');
        } else {
          console.error('Email failed to be sent');
        }
        setSubmitting(false);
      },
      onError: (error) => {
        console.error('Error sending email', error);
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
      {({ values, handleChange, isSubmitting }) => (
        <Form>
          <Box sx={{ display: 'flex', flexDirection: 'column' }}>
            <Field
              component={TextField}
              label="Email Address"
              name="emailAddress"
              type="email"
              fullWidth
              value={values.emailAddress}
              onChange={handleChange}
              required
            />
            <Field
              component={TextField}
              label="Object"
              name="emailObject"
              fullWidth
              value={values.emailObject}
              onChange={handleChange}
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
              value={values.emailBody}
              onChange={handleChange}
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
                type="submit"
                variant="contained"
                color="primary"
                disabled={isSubmitting}
              >
                {isSubmitting ? 'Sending...' : 'Send Email'}
              </Button>
            </div>
          </Box>
        </Form>
      )}
    </Formik>
  );
};

export default StixCoreObjectContentFilesDissemination;
