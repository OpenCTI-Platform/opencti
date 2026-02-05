import React, { useContext, useState } from 'react';
import moment from 'moment/moment';
import { UserContext } from '../../utils/hooks/useAuth';
import { daysBetweenDates, now } from '../../utils/Time';
import TopBanner, { TopBannerColor } from '../../components/TopBanner';
import { useFormatter } from '../../components/i18n';
import { RootSettings$data } from '../__generated__/RootSettings.graphql';
import { graphql } from 'react-relay';
import useApiMutation from '../../utils/hooks/useApiMutation';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import * as Yup from 'yup';
import { Field, Form, Formik } from 'formik';
import TextField from '../../components/TextField';
import { FormikConfig } from 'formik/dist/types';
import { Theme } from '@mui/material/styles/createTheme';
import { SxProps } from '@mui/material';

export const LICENSE_OPTION_TRIAL = 'trial';

const contactUsXtmHubMutation = graphql`
  mutation LicenseBannerContactUsMutation($message: String!) {
    contactUsXtmHub(message: $message) {
      success
    }
  }
`;

interface ContactUsInput {
  message: string;
}

interface BannerInfo {
  message: React.ReactNode;
  bannerColor: TopBannerColor;
  buttonText?: string;
  buttonStyle?: SxProps<Theme>;
  onButtonClick?: () => void;
}

const getBannerColor = (remainingDays: number) => {
  if (remainingDays <= 8) return 'gradient_yellow';
  if (remainingDays <= 22) return 'gradient_green';
  return 'gradient_blue';
};

const getButtonColor = (remainingDays: number): string => {
  if (remainingDays <= 8) return '#884106';
  if (remainingDays <= 22) return '#005744';
  return '#1e3a8a';
};

const getButtonStyle = (remainingDays: number): SxProps<Theme> => {
  const buttonColor = getButtonColor(remainingDays);

  return {
    color: 'white',
    fontWeight: 'bold',
    backgroundColor: buttonColor,
  };
};

const computeBannerInfo = (eeSettings: RootSettings$data['platform_enterprise_edition'], onButtonClick?: () => void): BannerInfo | undefined => {
  const { t_i18n } = useFormatter();
  if (!eeSettings.license_validated) {
    return {
      message: `The current ${eeSettings.license_type} license has expired, Enterprise Edition is disabled.`,
      bannerColor: 'red',
    };
  }
  if (eeSettings.license_extra_expiration) {
    return {
      message: `The current ${eeSettings.license_type} license has expired, Enterprise Edition will be disabled in ${eeSettings.license_extra_expiration_days} days.`,
      bannerColor: 'red',
    };
  }
  if (eeSettings.license_type === LICENSE_OPTION_TRIAL) {
    const remainingDays = daysBetweenDates(now(), moment(eeSettings.license_expiration_date));
    const buttonStyle = getButtonStyle(remainingDays);
    const bannerColor = getBannerColor(remainingDays);
    return {
      buttonText: t_i18n('Contact us'),
      buttonStyle,
      bannerColor,
      message: (
        <>
          {t_i18n('Your OpenCTI Enterprise Edition free trial is active: ')}
          <strong> {remainingDays} {remainingDays === 1 ? t_i18n('Day remaining') : t_i18n('Days remaining')}</strong>
        </>
      ),
      onButtonClick,
    };
  }
  return undefined;
};

const LicenseBanner = () => {
  const { t_i18n } = useFormatter();
  const { settings } = useContext(UserContext);
  const [showThankYouDialog, setShowThankYouDialog] = useState(false);
  const [showFormDialog, setShowFormDialog] = useState(false);
  const [commitContactUs] = useApiMutation(contactUsXtmHubMutation);
  const eeSettings = settings?.platform_enterprise_edition;
  const isEE = eeSettings?.license_enterprise;
  if (!isEE) return <></>;

  const onSubmit: FormikConfig<ContactUsInput>['onSubmit'] = (values) => {
    commitContactUs({
      variables: {
        message: values.message,
      },
      onCompleted: () => {
        setShowFormDialog(false);
        setShowThankYouDialog(true);
      },
    });
  };

  const bannerInfo = computeBannerInfo(eeSettings, () => {
    setShowFormDialog(true);
  });
  if (!bannerInfo) return <></>;

  const initialValues: ContactUsInput = {
    message: t_i18n('Please contact me about the OpenCTI free trial'),
  };

  const contactUsValidation = Yup.object().shape({
    message: Yup.string().required(t_i18n('This field is required')),
  });

  return (
    <>
      <TopBanner
        bannerText={bannerInfo.message}
        bannerColor={bannerInfo.bannerColor}
        buttonStyle={bannerInfo.buttonStyle}
        buttonText={bannerInfo.buttonText}
        onButtonClick={bannerInfo.onButtonClick}
      />
      <Dialog
        fullWidth={true}
        open={showFormDialog}
        onClose={() => setShowFormDialog(false)}
      >
        <DialogTitle>{t_i18n('Thank you!')}</DialogTitle>
        <Formik<ContactUsInput>
          initialValues={initialValues}
          validationSchema={contactUsValidation}
          onSubmit={onSubmit}
        >
          {({ submitForm, isSubmitting, resetForm }) => (
            <Form>
              <DialogContent>
                <Field
                  component={TextField}
                  name="message"
                  variant="standard"
                  multiline={true}
                  label={t_i18n('Your message')}
                  fullWidth={true}
                  minRows={5}
                />
              </DialogContent>
              <DialogActions>
                <Button
                  disabled={isSubmitting}
                  onClick={() => {
                    resetForm();
                    setShowFormDialog(false);
                  }}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button onClick={submitForm} disabled={isSubmitting} color="secondary">
                  {t_i18n('Validate')}
                </Button>
              </DialogActions>
            </Form>
          )}
        </Formik>
      </Dialog>
      <Dialog open={showThankYouDialog} onClose={() => setShowThankYouDialog(false)}>
        <DialogTitle>{t_i18n('Thank you!')}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t_i18n("Thank you for reaching out, we'll get back to you shortly.")}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowThankYouDialog(false)} color="primary">
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default LicenseBanner;
