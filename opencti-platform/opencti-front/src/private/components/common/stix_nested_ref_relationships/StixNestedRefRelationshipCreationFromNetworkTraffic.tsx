import IconButton from '@mui/material/IconButton';
import { Close } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import { Field, Formik } from 'formik';
import EntitySelectField from '@components/common/form/EntitySelectField';
import React from 'react';
import { useTheme } from '@mui/styles';
import Button from '@mui/material/Button';
import { FormikConfig } from 'formik/dist/types';
import { StixRefRelationshipAddInput } from '@components/cases/__generated__/CaseUtilsRelationAddMutation.graphql';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { fieldSpacingContainerStyle } from '../../../../utils/field';
import { minutesBefore, now } from '../../../../utils/Time';
import DateTimePickerField from '../../../../components/DateTimePickerField';

interface StixNestedRefRelationshipCreationFromNetworkTrafficProps {
  entityId: string;
  handleClose: () => void;
  typeFilter: string[];
  commit: (values: StixRefRelationshipAddInput) => Promise<unknown>;
}

interface StixNestedRefRelationshipAddInput {
  source: { label: string, type: string, value: string };
  start_time_source: string;
  stop_time_source: string;
  destination: { label: string, type: string, value: string };
  start_time_destination: string;
  stop_time_destination: string;
}

const StixNestedRefRelationshipCreationFromNetworkTraffic: React.FC<StixNestedRefRelationshipCreationFromNetworkTrafficProps> = ({
  entityId,
  handleClose,
  typeFilter,
  commit,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const onSubmit: FormikConfig<StixNestedRefRelationshipAddInput>['onSubmit'] = async (
    values,
    { setSubmitting, resetForm },
  ) => {
    const sourceId = values.source.value;
    const destinationId = values.destination.value;

    if (sourceId) {
      const input: StixRefRelationshipAddInput = {
        relationship_type: 'src',
        fromId: entityId,
        toId: sourceId,
        start_time: values.start_time_source,
        stop_time: values.stop_time_source,
      };
      try {
        await commit(input);
      } catch (error) {
        setSubmitting(false);
      }
    }

    if (destinationId) {
      const input: StixRefRelationshipAddInput = {
        relationship_type: 'dst',
        fromId: entityId,
        toId: destinationId,
        start_time: values.start_time_destination,
        stop_time: values.stop_time_destination,
      };
      try {
        await commit(input);
      } catch (error) {
        setSubmitting(false);
      }
    }

    setSubmitting(false);
    resetForm();
    handleClose();
  };

  return (
    <>
      <div style={{
        backgroundColor: theme.palette.background.nav,
        padding: '20px 20px 20px 60px',
      }}
      >
        <IconButton
          aria-label="Close"
          sx={{
            position: 'absolute',
            top: 12,
            left: 5,
            color: 'inherit',
          }}
          onClick={handleClose}
          size="large"
        >
          <Close fontSize="small" color="primary" />
        </IconButton>
        <Typography variant="h6" sx={{ float: 'left' }}>
          {t_i18n('Create a relationship')}
        </Typography>
        <div className="clearfix" />
      </div>
      <div
        style={{
          padding: '15px 0 0 15px',
          height: '100%',
          width: '100%',
        }}
      >
        <Formik
          initialValues={{
            source: { label: '', value: '', type: '' },
            start_time_source: minutesBefore(1, now()),
            stop_time_source: now(),
            destination: { label: '', value: '', type: '' },
            start_time_destination: minutesBefore(1, now()),
            stop_time_destination: now(),
          }}
          onSubmit={onSubmit}
          onReset={handleClose}
        >
          {({ submitForm, handleReset, isSubmitting }) => (
            <>
              <Field
                name="source"
                component={EntitySelectField}
                types={typeFilter}
                label={t_i18n('Source')}
              />
              <Field
                component={DateTimePickerField}
                name="start_time_source"
                textFieldProps={{
                  label: t_i18n('Source start time'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <Field
                component={DateTimePickerField}
                name="stop_time_source"
                textFieldProps={{
                  label: t_i18n('Source stop time'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <Field
                name="destination"
                component={EntitySelectField}
                types={typeFilter}
                label={t_i18n('Destination')}
                style={fieldSpacingContainerStyle}
              />
              <Field
                component={DateTimePickerField}
                name="start_time_destination"
                textFieldProps={{
                  label: t_i18n('Destination start time'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <Field
                component={DateTimePickerField}
                name="stop_time_destination"
                textFieldProps={{
                  label: t_i18n('Destination stop time'),
                  variant: 'standard',
                  fullWidth: true,
                  style: { marginTop: 20 },
                }}
              />
              <div
                style={{
                  marginTop: 20,
                  textAlign: 'right',
                }}
              >
                <Button
                  variant="contained"
                  onClick={handleReset}
                  disabled={isSubmitting}
                >
                  {t_i18n('Cancel')}
                </Button>
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={submitForm}
                  disabled={isSubmitting}
                  sx={{ marginLeft: theme.spacing(2) }}
                >
                  {t_i18n('Create')}
                </Button>
              </div>
            </>
          )}
        </Formik>
      </div>
    </>
  );
};

export default StixNestedRefRelationshipCreationFromNetworkTraffic;
