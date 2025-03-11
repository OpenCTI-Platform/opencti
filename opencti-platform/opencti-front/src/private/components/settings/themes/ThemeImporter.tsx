import React, { FormEvent, FunctionComponent } from 'react';
import * as Yup from 'yup';
import { Disposable, RecordSourceSelectorProxy } from 'relay-runtime';
import { IconButton } from '@mui/material';
import { FileUpload } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import { MESSAGING$ } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { ThemeCreationCreateMutation } from './__generated__/ThemeCreationCreateMutation.graphql';
import { createThemeMutation } from './ThemeCreation';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
import { insertNode } from '../../../../utils/store';
import { ThemesLinesSearchQuery$variables } from '../__generated__/ThemesLinesSearchQuery.graphql';

interface ThemeImporterProps {
  version: string;
  handleRefetch: () => Disposable;
  paginationOptions: ThemesLinesSearchQuery$variables;
}

const ThemeImporter: FunctionComponent<ThemeImporterProps> = ({
  version,
  handleRefetch,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [commit] = useApiMutation<ThemeCreationCreateMutation>(
    createThemeMutation,
    undefined,
    {
      successMessage: `${t_i18n('Theme')} ${t_i18n('successfully created')}`,
      errorMessage: t_i18n('Failed to import theme'),
    },
  );

  const themeValidator = Yup.object().shape({
    name: Yup.string()
      .trim()
      .min(2)
      .required(t_i18n('This field is required')),
    theme_background: Yup.string()
      .matches(/^#[0-9a-fA-F]{6}$/)
      .required(t_i18n('This field is required')),
    theme_paper: Yup.string()
      .matches(/^#[0-9a-fA-F]{6}$/)
      .required(t_i18n('This field is required')),
    theme_nav: Yup.string()
      .matches(/^#[0-9a-fA-F]{6}$/)
      .required(t_i18n('This field is required')),
    theme_primary: Yup.string()
      .matches(/^#[0-9a-fA-F]{6}$/)
      .required(t_i18n('This field is required')),
    theme_secondary: Yup.string()
      .matches(/^#[0-9a-fA-F]{6}$/)
      .required(t_i18n('This field is required')),
    theme_accent: Yup.string()
      .matches(/^#[0-9a-fA-F]{6}$/)
      .required(t_i18n('This field is required')),
    theme_logo: Yup.string().nullable(),
    theme_logo_collapsed: Yup.string().nullable(),
    theme_logo_login: Yup.string().nullable(),
  });
  const handleImport = (event: FormEvent) => {
    const inputElement = event.target as HTMLInputElement;
    const fileReader = new FileReader();
    const file = inputElement.files?.[0];
    if (!file) return;
    fileReader.readAsText(file, 'UTF-8');
    fileReader.onload = (e) => {
      try {
        let targetString;
        const target = e.target?.result;
        if (!target) throw Error(t_i18n('No file target found'));
        if (typeof target === 'string') {
          targetString = target;
        } else {
          targetString = new TextDecoder().decode(target);
        }

        const parsedFile = JSON.parse(targetString);
        if (!parsedFile) {
          // JSON.parse should throw a syntax error
          throw Error(t_i18n('Failed to parse file'));
        }

        if (parsedFile.openCTI_version !== version) {
          throw Error(t_i18n('', {
            id: 'Incompatible version. Please use version ....',
            values: { version },
          }));
        }
        if (parsedFile.type !== 'theme') {
          throw Error(t_i18n('Invalid type. Please import OpenCTI theme-type only'));
        }

        themeValidator.validate(parsedFile?.configuration)
          .then((t) => commit({
            variables: { input: t },
            updater: (store: RecordSourceSelectorProxy) => insertNode(
              store,
              'Pagination_themes',
              paginationOptions,
              'themeAdd',
            ),
            onCompleted: () => {
              handleRefetch();
            },
          }));
      } catch (err) {
        if (err instanceof Error) {
          MESSAGING$.notifyError(`${t_i18n('Failed to import theme')}: ${err.message}`);
        } else if (typeof err === 'string') {
          MESSAGING$.notifyError(`${t_i18n('Failed to import theme')}: ${err}`);
        } else {
          MESSAGING$.notifyError(t_i18n('Failed to import theme'));
        }
      }
    };
  };

  return (
    <IconButton
      color="primary"
      aria-label={t_i18n('Import')}
      size="large"
      component="label"
      onChange={handleImport}
    >
      <FileUpload fontSize="small" />
      <VisuallyHiddenInput type="file" accept={'application/json'} />
    </IconButton>
  );
};

export default ThemeImporter;
