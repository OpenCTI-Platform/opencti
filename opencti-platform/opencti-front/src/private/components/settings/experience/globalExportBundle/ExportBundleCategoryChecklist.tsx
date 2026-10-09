import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import FormControlLabel from '@mui/material/FormControlLabel';
import { Checkbox } from '@filigran/design-system';
import { useFormatter } from 'src/components/i18n';
import { GlobalExportBundleCategory } from '@components/settings/experience/globalExportBundle/globalExportBundleDrawer-utils';

interface ExportBundleCategoryChecklistProps {
  category: GlobalExportBundleCategory;
  checkedKeys: string[];
  showLabel: boolean;
  onToggleItem: (itemKey: string) => (checked: boolean | 'indeterminate') => void;
  accordionSx: Record<string, unknown>;
}

const ExportBundleCategoryChecklist: FunctionComponent<ExportBundleCategoryChecklistProps> = ({
  category,
  checkedKeys,
  showLabel,
  onToggleItem,
  accordionSx,
}) => {
  const { t_i18n } = useFormatter();
  const { items } = category;

  return (
    <>
      {showLabel && (
        <Typography variant="overline" color="textSecondary" sx={{ mt: 1 }}>
          {t_i18n(category.label)}
        </Typography>
      )}
      {items.map((item) => (
        <Accordion key={item.key} disableGutters expanded={false} sx={accordionSx}>
          <AccordionSummary sx={{ cursor: 'default' }}>
            <FormControlLabel
              onClick={(e) => e.stopPropagation()}
              control={(
                <Checkbox
                  checked={checkedKeys.includes(item.key)}
                  onCheckedChange={onToggleItem(item.key)}
                  style={{ marginRight: 10, marginLeft: 10 }}
                />
              )}
              label={<Typography fontWeight="bold">{t_i18n(item.label)}</Typography>}
            />
          </AccordionSummary>
        </Accordion>
      ))}
    </>
  );
};

export default ExportBundleCategoryChecklist;
