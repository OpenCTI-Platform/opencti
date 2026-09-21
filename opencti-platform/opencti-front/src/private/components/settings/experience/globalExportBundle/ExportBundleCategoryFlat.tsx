import React, { FunctionComponent } from 'react';
import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import FormControlLabel from '@mui/material/FormControlLabel';
import { Checkbox } from '@filigran/design-system';
import { useFormatter } from 'src/components/i18n';
import { GlobalExportBundleCategory } from '@components/settings/experience/globalExportBundle/globalExportBundleDrawer-utils';

interface ExportBundleCategoryFlatProps {
  category: GlobalExportBundleCategory;
  checked: boolean;
  onToggle: (checked: boolean | 'indeterminate') => void;
  accordionSx: Record<string, unknown>;
}

const ExportBundleCategoryFlat: FunctionComponent<ExportBundleCategoryFlatProps> = ({
  category,
  checked,
  onToggle,
  accordionSx,
}) => {
  const { t_i18n } = useFormatter();
  return (
    <Box sx={{ ...accordionSx, px: 2, py: 1.5 }}>
      <FormControlLabel
        control={(
          <Checkbox
            checked={checked}
            onCheckedChange={onToggle}
            style={{ marginRight: 10, marginLeft: 10 }}
          />
        )}
        label={<Typography fontWeight="bold">{t_i18n(category.label)}</Typography>}
      />
    </Box>
  );
};

export default ExportBundleCategoryFlat;
