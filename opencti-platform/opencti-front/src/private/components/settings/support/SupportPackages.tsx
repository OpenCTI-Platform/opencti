import React from 'react';
import CustomizationMenu from '@components/settings/CustomizationMenu';
import makeStyles from '@mui/styles/makeStyles';
import Button from '@mui/material/Button';
import { graphql } from 'react-relay';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import type { Theme } from '../../../../components/Theme';

const useStyles = makeStyles<Theme>(() => ({}));

export const supportPackageCreateQL = graphql`
    mutation SupportPackageAdd(
        $input: [SupportPackageAddInput!]!
    ) {
        supportPackageAdd(input: $input) {
            id
        }
    }
`;

const SupportPackages = () => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const generateSupportPackage = () => {
    alert('Go !');
  };

  return (
    <div className={classes.container}>
      <CustomizationMenu />
      <Breadcrumbs variant="list" elements={[{ label: t_i18n('Settings') }, { label: t_i18n('Customization') }, { label: t_i18n('Support packages'), current: true }]} />
      <Button
        aria-label="Generate support package"
        className={classes.createButton}
        onClick={generateSupportPackage}
        size="large"
        color="primary"
      >Generate support package
      </Button>
    </div>
  );
};

export default SupportPackages;
