import React, { FunctionComponent } from 'react';
import * as Yup from 'yup';
import { FormikConfig } from 'formik/dist/types';
import { Field, Form, Formik } from 'formik';
import { TextField } from 'formik-mui';
import Button from '@common/button/Button';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../../../../components/i18n';
import MarkdownField from '../../../../components/fields/MarkdownField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import type { Theme } from '../../../../components/Theme';
import { handleErrorInForm } from '../../../../relay/environment';
import { pictureManagementUtilsMutation } from './PictureManagementUtils';
import { PictureManagementUtils_node$data } from './__generated__/PictureManagementUtils_node.graphql';
import { PictureManagementUtilsMutation, StixDomainObjectFileEditInput } from './__generated__/PictureManagementUtilsMutation.graphql';
import SwitchField from '../../../../components/fields/SwitchField';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
}));

interface PictureManagementEditionProps {
  picture: PictureManagementUtils_node$data;
  entityId: string;
  handleClose: () => void;
}

interface PictureManagementEditionFormValues {
  id: string;
  description: string | null | undefined;
  inCarousel: boolean | null | undefined;
  order: number | null | undefined;
}

const PictureManagementEdition: FunctionComponent<PictureManagementEditionProps> = ({ picture, entityId, handleClose }) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
  const [commit] = useApiMutation<PictureManagementUtilsMutation>(
    pictureManagementUtilsMutation,
  );
  const pictureValidation = () => Yup.object().shape({
    description: Yup.string().nullable(),
    order: Yup.number().nullable().integer(t_i18n('The value must be a number')),
    inCarousel: Yup.boolean().nullable(),
  });
  const onSubmit: FormikConfig<PictureManagementEditionFormValues>['onSubmit'] = (values, { setSubmitting, setErrors }) => {
    const input: StixDomainObjectFileEditInput = {
      id: values.id,
      description: values.description,
      inCarousel: values.inCarousel,
      order: parseInt(String(values.order), 10),
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
    <Formik
      initialValues={{
        id: picture.id,
        description: picture.metaData?.description,
        inCarousel: picture.metaData?.inCarousel,
        order: picture.metaData?.order,
      }}
      validationSchema={pictureValidation}
      onSubmit={onSubmit}
    >
      {({ submitForm, isSubmitting, isValid }) => (
        <Form>
          <Field
            component={MarkdownField}
            name="description"
            label={t_i18n('Description')}
            fullWidth={true}
            multiline={true}
            rows="4"
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={TextField}
            variant="standard"
            name="order"
            label={t_i18n('Order of Carousel')}
            fullWidth={true}
            type="number"
            style={fieldSpacingContainerStyle}
          />
          <Field
            component={SwitchField}
            type="checkbox"
            name="inCarousel"
            label={t_i18n('In Carousel')}
            containerstyle={fieldSpacingContainerStyle}
          />
          <div className={classes.buttons}>
            <Button
              onClick={submitForm}
              disabled={isSubmitting || !isValid}
              classes={{ root: classes.button }}
            >
              {t_i18n('Update')}
            </Button>
          </div>
        </Form>
      )}
    </Formik>
  );
};

export default PictureManagementEdition;
