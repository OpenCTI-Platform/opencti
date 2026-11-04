import React from 'react';
import { UiSchema } from '@rjsf/utils';

export const NOTIFIER_CONNECTOR_EMAIL_ID = '6f5e30a8-56d5-4ff1-8b8d-f90243f771dc';
export const NOTIFIER_TITLE_VARIABLES_DOC = 'https://docs.opencti.io/latest/administration/tips-to-create-a-custom-notifier/#title-variables';

export const uiSchema: UiSchema = {
  'ui:options': {
    orderable: false,
    submitButtonOptions: {
      norender: true,
    },
  },
};

const NotifierTitleHelp = ({ t_i18n }: { t_i18n: (s: string) => string }) => (
  <>
    {t_i18n('Insert notification data with $ variables, e.g.')}{' '}
    <code>[$notification.name] $notification_content[0].title</code>
    {'. '}
    {t_i18n('A missing value is left empty.')}{' '}
    <a href={NOTIFIER_TITLE_VARIABLES_DOC} target="_blank" rel="noopener noreferrer">
      {t_i18n('See the available variables')}
    </a>
  </>
);

export const buildNotifierUiSchema = (
  connectorUiSchema: string | null | undefined,
  connectorId: string | undefined,
  t_i18n: (s: string) => string,
): UiSchema => {
  const schema: UiSchema = {
    ...JSON.parse(connectorUiSchema ?? '{}'),
    ...uiSchema,
  };
  if (connectorId === NOTIFIER_CONNECTOR_EMAIL_ID) {
    schema.title = {
      ...schema.title,
      'ui:help': <NotifierTitleHelp t_i18n={t_i18n} />,
    };
  }
  return schema;
};
