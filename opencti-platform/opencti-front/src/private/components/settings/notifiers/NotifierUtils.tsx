import React from 'react';
import { FieldTemplateProps, UiSchema } from '@rjsf/utils';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import { InfoOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';

export const NOTIFIER_TITLE_VARIABLES_DOC = 'https://docs.opencti.io/latest/administration/tips-to-create-a-custom-notifier/#title-variables';

export const uiSchema: UiSchema = {
  'ui:options': {
    orderable: false,
    submitButtonOptions: {
      norender: true,
    },
  },
};

// How to insert notification data, shown once above the title: the title takes $ variables, the template EJS
export const NotifierVariablesHelp = () => {
  const { t_i18n } = useFormatter();
  return (
    <Typography
      variant="caption"
      color="textSecondary"
      component="div"
      sx={{ display: 'flex', alignItems: 'center', gap: 0.5, marginBottom: 2 }}
    >
      <span>{t_i18n('Insert notification data with variables in the title or the template.')}</span>
      <Tooltip>
        <TooltipTrigger asChild>
          <InfoOutlined
            fontSize="small"
            tabIndex={0}
            role="img"
            aria-hidden={false}
            aria-label={t_i18n('How to insert notification data')}
          />
        </TooltipTrigger>
        <TooltipContent>
          <div>
            {t_i18n('In the title, use $ variables, e.g.')}{' '}
            <code>$notification.name</code>{', '}<code>$notification_content[0].title</code>
            {'. '}
            {t_i18n('A missing value is left empty.')}
          </div>
          <div>
            {t_i18n('In the template, use EJS, e.g.')}{' '}
            <code>{'<%= notification_content[0].title %>'}</code>
          </div>
        </TooltipContent>
      </Tooltip>
      <a href={NOTIFIER_TITLE_VARIABLES_DOC} target="_blank" rel="noopener noreferrer">
        {t_i18n('See the available variables')}
      </a>
    </Typography>
  );
};

// The help sits above the field, which neither ui:help nor ui:description can do: the MUI theme renders both below it.
// Defined once at module level: a component built on each render would remount the input and lose its focus
const NotifierVariablesHelpFieldTemplate = (props: FieldTemplateProps) => {
  const { FieldTemplate } = props.registry.templates;
  return (
    <>
      <NotifierVariablesHelp />
      <FieldTemplate {...props} />
    </>
  );
};

// Templates a connector ui schema can name, as 'ui:FieldTemplate': '<name>' (the Platform mailer does it on its title).
// Registered on the notifier forms
export const notifierFormTemplates = { NotifierVariablesHelpFieldTemplate };

export const buildNotifierUiSchema = (connectorUiSchema: string | null | undefined): UiSchema => ({
  ...JSON.parse(connectorUiSchema ?? '{}'),
  ...uiSchema,
});
