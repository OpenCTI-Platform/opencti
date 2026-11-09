import React, { ReactNode } from 'react';
import { FieldTemplateProps, helpId, UiSchema, WidgetProps } from '@rjsf/utils';
import { Text } from '@filigran/design-system';
import { OpenInNewOutlined } from '@mui/icons-material';
import Box from '@mui/material/Box';
import FormHelperText from '@mui/material/FormHelperText';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

export const NOTIFIER_TITLE_VARIABLES_DOC = 'https://docs.opencti.io/latest/administration/tips-to-create-a-custom-notifier/#title-variables';

// Variable helpers a connector ui schema can set as 'ui:FieldTemplate', and the title input as 'ui:widget'
// (the Platform mailer sets them on its title and template)
export const TITLE_VARIABLE_HELPER = 'TitleVariableHelper';
export const TEMPLATE_VARIABLE_HELPER = 'TemplateVariableHelper';
export const TITLE_VARIABLE_INPUT = 'TitleVariableInput';

export const uiSchema: UiSchema = {
  'ui:options': {
    orderable: false,
    submitButtonOptions: {
      norender: true,
    },
  },
};

// The theme gives every <code> a colored chip with !important: the helper shows a plain monospace inline instead.
// It takes the helper color, except an example, which stands out in the text color
const InlineCode = ({ children, isExample = false }: { children: ReactNode; isExample?: boolean }) => (
  <Box
    component="code"
    sx={{
      fontFamily: 'Consolas, monaco, monospace',
      fontSize: 'inherit',
      padding: '0 !important',
      background: 'none !important',
      color: (theme: Theme) => `${isExample ? theme.palette.text.primary : 'inherit'} !important`,
    }}
  >
    {children}
  </Box>
);

// How to insert notification data, shown once above the title
export const VariableHelperIntro = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <Text as="div" variant="content-compact" className="mb-4 text-input-label">
      {t_i18n('Insert notification data with variables in the title or the template.')}{' '}
      <Text
        as="a"
        variant="content-compact-link"
        href={NOTIFIER_TITLE_VARIABLES_DOC}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center gap-1"
        style={{ color: theme.palette.primary.main }}
      >
        {t_i18n('See the available variables')}
        <OpenInNewOutlined sx={{ fontSize: 14 }} />
      </Text>
    </Text>
  );
};

// Shown below the field, in the helper color of the design system fields (Name, Description...),
// with the help id the input already lists in its aria-describedby
const VariableHelperText = ({ fieldId, children }: { fieldId: string; children: ReactNode }) => (
  <FormHelperText component="div" id={helpId(fieldId)} sx={{ marginTop: 1, color: 'var(--text-input-helper)' }}>
    {children}
  </FormHelperText>
);

const TitleVariableHelperText = ({ fieldId }: { fieldId: string }) => {
  const { t_i18n } = useFormatter();
  return (
    <VariableHelperText fieldId={fieldId}>
      {t_i18n('Use {variable}, e.g. {example}. A missing value is left empty.', {
        values: {
          variable: <InlineCode>$variable</InlineCode>,
          example: <InlineCode isExample>$notification_content[0].title</InlineCode>,
        },
      })}
    </VariableHelperText>
  );
};

const TemplateVariableHelperText = ({ fieldId }: { fieldId: string }) => {
  const { t_i18n } = useFormatter();
  return (
    <VariableHelperText fieldId={fieldId}>
      {t_i18n('Use EJS, e.g. {example}', {
        values: { example: <InlineCode isExample>{'<%= notification_content[0].title %>'}</InlineCode> },
      })}
    </VariableHelperText>
  );
};

// Defined once at module level: a component built on each render would remount the input and lose its focus.
// The intro sits above the title, which neither ui:help nor ui:description can do: the MUI theme renders both below the field
const TitleVariableHelper = (props: FieldTemplateProps) => {
  const { FieldTemplate } = props.registry.templates;
  return (
    <>
      <VariableHelperIntro />
      <FieldTemplate {...props} help={<TitleVariableHelperText fieldId={props.id} />} />
    </>
  );
};

const TemplateVariableHelper = (props: FieldTemplateProps) => {
  const { FieldTemplate } = props.registry.templates;
  return <FieldTemplate {...props} help={<TemplateVariableHelperText fieldId={props.id} />} />;
};

// Registered as rjsf templates on the notifier forms
export const variableHelperTemplates = {
  [TITLE_VARIABLE_HELPER]: TitleVariableHelper,
  [TEMPLATE_VARIABLE_HELPER]: TemplateVariableHelper,
};

// The default text input with a translated example as placeholder (a field template cannot reach the placeholder).
// A placeholder the connector declares wins
const TitleVariableInput = (props: WidgetProps) => {
  const { t_i18n } = useFormatter();
  const { TextWidget } = props.registry.widgets;
  return <TextWidget {...props} placeholder={props.placeholder || t_i18n('e.g. New alert: $notification.name')} />;
};

// Registered as rjsf widgets on the notifier forms
export const variableHelperWidgets = {
  [TITLE_VARIABLE_INPUT]: TitleVariableInput,
};

export const buildNotifierUiSchema = (connectorUiSchema: string | null | undefined): UiSchema => ({
  ...JSON.parse(connectorUiSchema ?? '{}'),
  ...uiSchema,
});
