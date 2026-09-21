import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import FormControlLabel from '@mui/material/FormControlLabel';
import { Checkbox } from '@filigran/design-system';
import { useFormatter } from 'src/components/i18n';
import { GlobalExportBundleCategory } from '@components/settings/experience/globalExportBundle/globalExportBundleDrawer-utils';

interface ExportBundleCategoryPlaceholderProps {
  category: GlobalExportBundleCategory;
  accordionSx: Record<string, unknown>;
}

const ExportBundleCategoryPlaceholder: FunctionComponent<ExportBundleCategoryPlaceholderProps> = ({
  category,
  accordionSx,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Accordion disableGutters expanded={false} sx={{ ...accordionSx, opacity: 0.5 }}>
      <AccordionSummary sx={{ cursor: 'default' }}>
        <FormControlLabel
          control={<Checkbox disabled checked={false} style={{ marginRight: 10, marginLeft: 10 }} />}
          label={<Typography fontWeight="bold">{t_i18n(category.label)}</Typography>}
        />
      </AccordionSummary>
    </Accordion>
  );
};

export default ExportBundleCategoryPlaceholder;
