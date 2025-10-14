import { type JsonSchema, type JsonSchema7 } from '@jsonforms/core';
import { fieldSpacingContainerStyle } from '../../../utils/field';
import Alert from '@mui/material/Alert';
import { JsonForms } from '@jsonforms/react';
import { customRenderers } from '@components/data/IngestionCatalog/IngestionCatalogConnectorCreation';
import { Accordion, AccordionSummary } from '../../../components/Accordion';
import Typography from '@mui/material/Typography';
import AccordionDetails from '@mui/material/AccordionDetails';
import React from 'react';
import { useFormatter } from '../../../components/i18n';

const AuthProviderJsonForm = ({ schema, handleChange }: { schema: JsonSchema, handleChange: (data: unknown) => void }) => {
  const { t_i18n } = useFormatter();

  const requiredProperties: Record<string, JsonSchema7> = {};
  const optionalProperties: Record<string, JsonSchema7> = {};
  const defaults: Record<string, unknown> = {};
  Object.entries(schema?.properties ?? []).forEach(([key, value]) => {
    if (schema?.required?.includes(key)) {
      requiredProperties[key] = value;
    } else {
      optionalProperties[key] = value;
    }

    if (value.default !== undefined) {
      defaults[key] = value.default;
    }
  });
  const reqProperties: JsonSchema = {
    properties: requiredProperties,
    required: schema?.required,
  };

  const optProperties: JsonSchema = {
    properties: optionalProperties,
  };
  const hasRequiredProperties = Object.keys(reqProperties.properties || {}).length > 0;
  const hasOptionalProperties = Object.keys(optProperties.properties || {}).length > 0;
  return (
    <>
      {(hasRequiredProperties || hasOptionalProperties) && (
        <>
          <div style={fieldSpacingContainerStyle}>{t_i18n('Configuration')}</div>
          {
            hasRequiredProperties && (
              <Alert
                severity="info"
                icon={false}
                variant="outlined"
                style={{
                  position: 'relative',
                  width: '100%',
                  marginTop: 8,
                }}
                slotProps={{
                  message: {
                    style: {
                      width: '100%',
                      overflow: 'visible',
                    },
                  },
                }}
              >

                <JsonForms
                  data={defaults}
                  schema={reqProperties}
                  renderers={customRenderers}
                  validationMode={'NoValidation'}
                  onChange={handleChange}
                />
              </Alert>
            )
          }

          {hasOptionalProperties && (
            <div style={fieldSpacingContainerStyle}>
              <Accordion slotProps={{ transition: { unmountOnExit: false } }}>
                <AccordionSummary id="accordion-panel">
                  <Typography>{t_i18n('Advanced options')}</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <JsonForms
                    data={defaults}
                    schema={optProperties}
                    renderers={customRenderers}
                    validationMode={'NoValidation'}
                    onChange={handleChange}
                  />
                </AccordionDetails>
              </Accordion>
            </div>
          )}
        </>
      )}
    </>
  );
};

export default AuthProviderJsonForm;
