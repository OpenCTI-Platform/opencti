import { useMutation } from 'react-relay';
import React, { FunctionComponent } from 'react';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { Field, Form, Formik } from 'formik';
import { TextField } from 'formik-mui';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/MarkdownField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import SwitchField from '../../../../components/SwitchField';
import {
  StixDomainObjectFileEditInput,
} from './__generated__/PictureManagementEditionMutation.graphql';
import { Theme } from '../../../../components/Theme';
import { pictureLineMutation } from './PictureLine';
import { PictureLineMutation } from './__generated__/PictureLineMutation.graphql';
import { PictureLine_node$data } from './__generated__/PictureLine_node.graphql';
import { handleErrorInForm } from '../../../../relay/environment';

const useStyles = makeStyles<Theme>((theme) => ({
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
}));

interface PictureManagementEditionProps {
  picture: PictureLine_node$data
  entityId: string
  handleClose: () => void;
}

interface PictureManagementEditionFormValues {
  id: string
  description: string | null;
  order: number | null;
  inCarousel: boolean | null;
}

const PictureManagementEdition: FunctionComponent<PictureManagementEditionProps> = ({
  picture,
  entityId,
  handleClose,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const [commit] = useMutation<PictureLineMutation>(pictureLineMutation);
  const pictureValidation = () => Yup.object().shape({
    description: Yup.string().nullable(),
    order: Yup.number().nullable().integer(t('The value must be a number')),
    inCarousel: Yup.boolean(),
  });
  const onSubmit: FormikConfig<PictureManagementEditionFormValues>['onSubmit'] = (
    values,
    { setSubmitting, setErrors },
  ) => {
    const input: StixDomainObjectFileEditInput = {
      id: values.id,
      description: values.description,
      order: values.order,
      inCarousel: values.inCarousel,
    };
    commit({
      variables: {
        id: entityId,
        input,
      },
      onCompleted: () => {
        setSubmitting(false);
        handleClose();
      },
      onError: (error: Error) => {
        handleErrorInForm(error, setErrors);
        setSubmitting(false);
      },
    });
  };

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
          {t('Update a picture')}
        </Typography>
        <div className="clearfix" />
      </div>
      <div className={classes.container}>
        <Formik
          initialValues={{
            id: picture.id,
            description: picture.description,
            order: picture.order,
            inCarousel: picture.inCarousel,
          }}
          validationSchema={pictureValidation}
          onSubmit={onSubmit}
        >
          {({ submitForm, isSubmitting, isValid }) => (
          <Form style={{ margin: '20px 0 20px 0' }}>
            <Field
              component={MarkdownField}
              name="description"
              label={t('Description')}
              fullWidth={true}
              multiline={true}
              rows="4"
              style={fieldSpacingContainerStyle}
            />
            <Field
              component={TextField}
              variant="standard"
              name="order"
              label={t('Order')}
              fullWidth={true}
              type="number"
              style={{ marginTop: 20 }}
            />
            <Field
              component={SwitchField}
              type="checkbox"
              name="inCarousel"
              label={t('In Carousel?')}
              containerstyle={fieldSpacingContainerStyle}
            />
            <div className={classes.buttons}>
              <Button
                variant="contained"
                color="primary"
                onClick={submitForm}
                disabled={isSubmitting || !isValid}
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

export default PictureManagementEdition;
