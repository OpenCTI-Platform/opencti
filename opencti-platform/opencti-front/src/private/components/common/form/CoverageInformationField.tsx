import React, { FunctionComponent, ReactElement } from 'react';
import { Field, FieldArray } from 'formik';
import Button from '@mui/material/Button';
import { IconButton } from '@mui/material';
import { AddOutlined, DeleteOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import OpenVocabField from '@components/common/form/OpenVocabField';
import { useFormatter } from '../../../../components/i18n';
import TextField from '../../../../components/TextField';
import { fieldSpacingContainerStyle } from '../../../../utils/field';

interface CoverageInformationInput {
  coverage_name: string;
  coverage_score: number | string;
}

interface CoverageInformationFieldProps {
  name: string;
  values: CoverageInformationInput[];
  containerStyle?: React.CSSProperties;
  setFieldValue?: (name: string, value: unknown) => void;
}

const CoverageInformationField: FunctionComponent<CoverageInformationFieldProps> = ({
  name,
  values,
  containerStyle,
}): ReactElement => {
  const { t_i18n } = useFormatter();

  return (
    <div style={{ ...fieldSpacingContainerStyle, ...containerStyle }}>
      <Typography variant="h4" gutterBottom>
        {t_i18n('Coverage information')}
      </Typography>
      <FieldArray name={name} render={(arrayHelpers) => (
        <>
          <div>
            {values?.map((_, index) => (
              <div
                key={index}
                style={{
                  marginTop: index === 0 ? 10 : 20,
                  width: '100%',
                  position: 'relative',
                  paddingRight: 50,
                }}
              >
                <div
                  style={{
                    display: 'grid',
                    gap: 20,
                    gridTemplateColumns: '1fr 1fr',
                  }}
                >
                  <OpenVocabField
                    label={t_i18n('Coverage name')}
                    type="coverage_ov"
                    name={`${name}.${index}.coverage_name`}
                    required={true}
                    onChange={(__, value) => {
                      arrayHelpers.replace(index, { ...values[index], coverage_name: value.toString() });
                    }}
                    containerStyle={{ marginTop: 3, width: '100%' }}
                    multiple={false}
                  />
                  <Field
                    component={TextField}
                    variant="standard"
                    name={`${name}.${index}.coverage_score`}
                    label={t_i18n('Coverage score (0-100)')}
                    type="number"
                    fullWidth
                    required
                    slotProps={{
                      input: {
                        inputProps: {
                          min: 0,
                          max: 100,
                        },
                      },
                    }}
                  />
                </div>
                <IconButton
                  id={`deleteCoverageInfo_${index}`}
                  aria-label="Delete"
                  onClick={() => {
                    arrayHelpers.remove(index);
                  }}
                  size="large"
                  style={{ position: 'absolute', right: -10, top: 5 }}
                >
                  <DeleteOutlined />
                </IconButton>
              </div>
            ))}
            <Button
              size="small"
              startIcon={<AddOutlined />}
              variant="contained"
              color="primary"
              aria-label="Add"
              id="addCoverageInfo"
              onClick={() => {
                arrayHelpers.push({ coverage_name: '', coverage_score: '' });
              }}
              style={{ marginTop: 20 }}
            >
              {t_i18n('Add coverage metric')}
            </Button>
          </div>
        </>
      )}
      />
    </div>
  );
};

export default CoverageInformationField;
