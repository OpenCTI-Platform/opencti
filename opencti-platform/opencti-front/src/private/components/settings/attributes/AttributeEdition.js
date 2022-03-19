import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { Formik, Form, Field } from 'formik';
import { compose, pick } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import { TextField } from 'formik-mui';
import * as Yup from 'yup';
import { ConnectionHandler } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import { commitMutation } from '../../../../relay/environment';

const styles = (theme) => ({
  header: {
    backgroundColor: theme.palette.background.nav,
    padding: '20px 20px 20px 60px',
  },
  closeButton: {
    position: 'absolute',
    top: 12,
    left: 5,
    color: 'inherit',
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
  appBar: {
    width: '100%',
    zIndex: theme.zIndex.drawer + 1,
    borderBottom: '1px solid #5c5c5c',
  },
  title: {
    float: 'left',
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
});

const attributeMutationUpdate = graphql`
  mutation AttributeEditionUpdateMutation(
    $id: String!
    $previous: String!
    $current: String!
  ) {
    runtimeAttributeEdit(id: $id, previous: $previous, current: $current)
  }
`;

const attributeValidation = (t) => Yup.object().shape({
  value: Yup.string().required(t('This field is required')),
});

const AttributeEditionContainer = (props) => {
  const { t } = useFormatter();
  const { classes, handleClose, attribute, paginationOptions } = props;
  const [previous] = useState(attribute.value);

  const onSubmit = (values, { setSubmitting }) => {
    const current = values.value;
    if (current !== previous) {
      commitMutation({
        mutation: attributeMutationUpdate,
        variables: { id: attribute.key, previous, current },
        setSubmitting,
        updater: (store) => {
          const record = store.get(store.getRoot().getDataID());
          const conn = ConnectionHandler.getConnection(
            record,
            'Pagination_runtimeAttributes',
            paginationOptions,
          );
          ConnectionHandler.deleteNode(conn, previous);
        },
        onCompleted: () => {
          setSubmitting(false);
          handleClose();
        },
      });
    } else {
      setSubmitting(false);
      handleClose();
    }
  };

  const initialValues = pick(['value'], attribute);
  return (
    <div>
      <div className={classes.header}>
        <IconButton
          aria-label="Close"
          className={classes.closeButton}
          onClick={handleClose}
          size="large"
          color="primary"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" classes={{ root: classes.title }}>
          {t('Update an attribute')}
        </Typography>
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Formik
          enableReinitialize={true}
          initialValues={initialValues}
          validationSchema={attributeValidation(t)}
          onSubmit={onSubmit}
        >
          {({ submitForm, isSubmitting }) => (
            <Form style={{ margin: '20px 0 20px 0' }}>
              <Field
                component={TextField}
                variant="standard"
                name="value"
                label={t('Type')}
                fullWidth={true}
              />
              <div className={classes.buttons}>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  classes={{ root: classes.button }}
                >
                  {t('Update')}
                </Button>
              </div>
            </Form>
          )}
        </Formik>
      </div>
    </div>
  );
};

export default compose(withStyles(styles, { withTheme: true }))(
  AttributeEditionContainer,
);
