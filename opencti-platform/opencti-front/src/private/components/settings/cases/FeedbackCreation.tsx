import React, { FunctionComponent } from 'react';
import { Field, Form, Formik } from 'formik';
import Drawer from '@mui/material/Drawer';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import * as Yup from 'yup';
import { graphql, useMutation } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import { FormikConfig } from 'formik/dist/types';
import Rating, { IconContainerProps } from '@mui/material/Rating';
import SentimentVeryDissatisfiedIcon from '@mui/icons-material/SentimentVeryDissatisfied';
import SentimentDissatisfiedIcon from '@mui/icons-material/SentimentDissatisfied';
import SentimentSatisfiedIcon from '@mui/icons-material/SentimentSatisfied';
import SentimentSatisfiedAltIcon from '@mui/icons-material/SentimentSatisfiedAltOutlined';
import SentimentVerySatisfiedIcon from '@mui/icons-material/SentimentVerySatisfied';
import { styled } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import MarkDownField from '../../../../components/MarkDownField';
import { Theme } from '../../../../components/Theme';
import { FeedbackCreationMutation$variables } from './__generated__/FeedbackCreationMutation.graphql';
import { MESSAGING$ } from '../../../../relay/environment';
import StixCoreObjectsField from '../../common/form/StixCoreObjectsField';

const useStyles = makeStyles<Theme>((theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: '50%',
    position: 'fixed',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    padding: 0,
  },
  createButton: {
    position: 'fixed',
    bottom: 30,
    right: 230,
  },
  buttons: {
    marginTop: 20,
    textAlign: 'right',
  },
  button: {
    marginLeft: theme.spacing(2),
  },
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
  importButton: {
    position: 'absolute',
    top: 15,
    right: 20,
  },
  container: {
    padding: '10px 20px 20px 20px',
  },
}));

export const StyledRating = styled(Rating)(({ theme }) => ({
  '& .MuiRating-iconEmpty .MuiSvgIcon-root': {
    color: theme.palette.action.disabled,
  },
}));

export const customIcons: {
  [index: string]: {
    icon: React.ReactElement;
    label: string;
  };
} = {
  1: {
    icon: <SentimentVeryDissatisfiedIcon color="error" />,
    label: 'Very Dissatisfied',
  },
  2: {
    icon: <SentimentDissatisfiedIcon color="error" />,
    label: 'Dissatisfied',
  },
  3: {
    icon: <SentimentSatisfiedIcon color="warning" />,
    label: 'Neutral',
  },
  4: {
    icon: <SentimentSatisfiedAltIcon color="success" />,
    label: 'Satisfied',
  },
  5: {
    icon: <SentimentVerySatisfiedIcon color="success" />,
    label: 'Very Satisfied',
  },
};

export function IconContainer(props: IconContainerProps) {
  const { value, ...other } = props;
  return <span {...other}>{customIcons[value].icon}</span>;
}

const caseMutation = graphql`
  mutation FeedbackCreationMutation($input: CaseAddInput!) {
    caseAdd(input: $input) {
      ...CaseLine_node
    }
  }
`;

const caseValidation = (t: (v: string) => string) => Yup.object().shape({
  name: Yup.string().required(t('This field is required')),
  description: Yup.string().nullable(),
  rating: Yup.number(),
});

interface CaseAddInput {
  name: string,
  description: string,
  rating: number,
  objects: [],
}

const FeedbackCreation: FunctionComponent<{
  openDrawer: boolean,
  handleCloseDrawer: () => void,
}> = ({
  openDrawer,
  handleCloseDrawer,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();

  const [commit] = useMutation(caseMutation);

  const onSubmit: FormikConfig<CaseAddInput>['onSubmit'] = (
    values,
    {
      setSubmitting,
      resetForm,
    },
  ) => {
    const finalValues : FeedbackCreationMutation$variables['input'] = {
      name: values.name,
      type: 'feedback',
      description: values.description,
      rating: parseInt(String(values.rating), 6),
    };
    commit({
      variables: {
        input: finalValues,
      },
      onCompleted: () => {
        setSubmitting(false);
        resetForm();
        handleCloseDrawer();
        MESSAGING$.notifySuccess('Thank you for your feedback !');
      },
    });
  };

  return (
    <div>
      <Drawer
        open={openDrawer}
        anchor="right"
        elevation={1}
        sx={{ zIndex: 1202 }}
        classes={{ paper: classes.drawerPaper }}
        onClose={handleCloseDrawer}
      >
        <div className={classes.header}>
          <IconButton
            aria-label="Close"
            className={classes.closeButton}
            onClick={handleCloseDrawer}
            size="large"
            color="primary"
          >
            <Close fontSize="small" color="primary" />
          </IconButton>
          <Typography variant="h6">{t('Submit a Feedback')}</Typography>
        </div>
        <div className={classes.container}>
          <Formik<CaseAddInput>
            initialValues={{
              name: '',
              description: '',
              rating: 5,
              objects: [],
            }}
            validationSchema={caseValidation(t)}
            onSubmit={onSubmit}
            onReset={handleCloseDrawer}
          >
            {({
              submitForm,
              handleReset,
              isSubmitting,
              setFieldValue,
              values,
            }) => (
              <Form style={{ margin: '20px 0 20px 0' }}>
                <Field
                  component={TextField}
                  variant="standard"
                  name="name"
                  label={t('Name')}
                  fullWidth={true}
                />
                <Field
                  component={MarkDownField}
                  name="description"
                  label={t('Description')}
                  fullWidth={true}
                  multiline={true}
                  rows="4"
                  style={{ marginTop: 20 }}
                />
                <StyledRating
                  name='highlight-selected-only'
                  value={values.rating}
                  IconContainerComponent={IconContainer}
                  onChange={(_, newValue) => {
                    setFieldValue('rating', newValue);
                  }}
                  highlightSelectedOnly
                  style={{ marginTop: 20 }}
                />
                <StixCoreObjectsField
                  name="objects"
                  style={{ width: '100%' }}
                  setFieldValue={setFieldValue}
                  values={values.objects}
                />
                <div className={classes.buttons}>
                  <Button
                    variant="contained"
                    onClick={handleReset}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Cancel')}
                  </Button>
                  <Button
                    variant="contained"
                    color="secondary"
                    onClick={submitForm}
                    disabled={isSubmitting}
                    classes={{ root: classes.button }}
                  >
                    {t('Create')}
                  </Button>
                </div>
              </Form>
            )}
          </Formik>
        </div>
      </Drawer>
    </div>
  );
};

export default FeedbackCreation;
