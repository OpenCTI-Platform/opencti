import React from 'react';
import { Box, Button, TextField, Typography } from '@mui/material';
import { graphql, useMutation } from 'react-relay';
import { Field, Form, Formik } from 'formik';

interface StixCoreObjectContentFilesDisseminationProps {
  fileId: string;
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
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Typography variant="h6"> Diffusion Form </Typography>
            <Field
              as={TextField}
              label="Email Address"
              name="emailAddress"
              type="email"
              fullWidth
              value={values.emailAddress}
              onChange={handleChange}
              required
            />
            <Field
              as={TextField}
              label="Object"
              name="emailObject"
              fullWidth
              value={values.emailObject}
              onChange={handleChange}
              required
            />
            <Field
              as={TextField}
              label="Body"
              name="emailBody"
              multiline
              rows={6}
              fullWidth
              value={values.emailBody}
              onChange={handleChange}
              required
            />
            <Button
              type="submit"
              variant="contained"
              color="primary"
              disabled={isSubmitting}
            >
              {isSubmitting ? 'Sending...' : 'Send Email'}
            </Button>
          </Box>
        </Form>
      )}
    </Formik>
  );
};

export default StixCoreObjectContentFilesDissemination;
