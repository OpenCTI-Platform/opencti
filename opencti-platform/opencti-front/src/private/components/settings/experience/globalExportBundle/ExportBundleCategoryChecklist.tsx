import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Accordion from '@mui/material/Accordion';
import AccordionSummary from '@mui/material/AccordionSummary';
import AccordionDetails from '@mui/material/AccordionDetails';
import FormControlLabel from '@mui/material/FormControlLabel';
import { Checkbox } from '@filigran/design-system';
import ExpandMoreOutlined from '@mui/icons-material/ExpandMoreOutlined';
import { useFormatter } from 'src/components/i18n';
import { GlobalExportBundleCategory } from '@components/settings/experience/globalExportBundle/globalExportBundleDrawer-utils';

interface ExportBundleCategoryChecklistProps {
  category: GlobalExportBundleCategory;
  checkedKeys: string[];
  onToggleAll: (checked: boolean | 'indeterminate') => void;
  onToggleItem: (itemKey: string) => (checked: boolean | 'indeterminate') => void;
  accordionSx: Record<string, unknown>;
}

const ExportBundleCategoryChecklist: FunctionComponent<ExportBundleCategoryChecklistProps> = ({
  category,
  checkedKeys,
  onToggleAll,
  onToggleItem,
  accordionSx,
}) => {
  const { t_i18n } = useFormatter();
  const items = category.items ?? [];
  const allChecked = items.length > 0 && checkedKeys.length === items.length;
  const someChecked = checkedKeys.length > 0 && checkedKeys.length < items.length;

  return (
    <Accordion disableGutters sx={accordionSx}>
      <AccordionSummary expandIcon={<ExpandMoreOutlined />}>
        <FormControlLabel
          onClick={(e) => e.stopPropagation()}
          control={(
            <Checkbox
              checked={someChecked ? 'indeterminate' : allChecked}
              style={{ marginRight: 10, marginLeft: 10 }}
              onCheckedChange={onToggleAll}
            />
          )}
          label={(
            <Typography fontWeight="bold">
              {t_i18n(category.label)} ({checkedKeys.length}/{items.length})
            </Typography>
          )}
        />
      </AccordionSummary>
      <AccordionDetails sx={{ display: 'flex', flexDirection: 'column', paddingLeft: 5, paddingTop: 0, marginTop: -1 }}>
        {items.map((item) => (
          <FormControlLabel
            key={item.key}
            control={(
              <Checkbox
                checked={checkedKeys.includes(item.key)}
                onCheckedChange={onToggleItem(item.key)}
                style={{ marginRight: 10, marginLeft: 10 }}
              />
            )}
            label={t_i18n(item.label)}
          />
        ))}
      </AccordionDetails>
    </Accordion>
  );
};

export default ExportBundleCategoryChecklist;
