import React from 'react';
import { Form, Formik } from 'formik';
import { Dialog, DialogBody, DialogContent, DialogFooter, DialogTitle } from '@filigran/design-system';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../components/i18n';
import { FieldOption, fieldSpacingContainerStyle } from '../../../../utils/field';
import ObjectMarkingField from '../form/ObjectMarkingField';
import ObjectLabelField from '../form/ObjectLabelField';
import ConfidenceField from '../form/ConfidenceField';
import type { EnrichmentValues } from './useContentMappingActions';

interface MappingEnrichmentDialogProps {
  open: boolean;
  count: number;
  onClose: () => void;
  onSubmit: (values: EnrichmentValues) => void;
}

interface FormValues {
  objectMarking: FieldOption[];
  objectLabel: FieldOption[];
  confidence: string;
}

// Markings, labels and confidence applied to the objects created by a bulk validation (US.5).
const MappingEnrichmentDialog = ({ open, count, onClose, onSubmit }: MappingEnrichmentDialogProps) => {
  const { t_i18n } = useFormatter();
  return (
    <Dialog open={open} onOpenChange={(isOpen) => !isOpen && onClose()}>
      <DialogContent>
        <DialogTitle>{`${t_i18n('Validate')} ${count} ${t_i18n(count > 1 ? 'objects' : 'object')}`}</DialogTitle>
        <Formik<FormValues>
          initialValues={{ objectMarking: [], objectLabel: [], confidence: '' }}
          onSubmit={(values) => {
            onSubmit({
              objectMarking: values.objectMarking.map((o) => o.value),
              objectLabel: values.objectLabel.map((o) => o.value),
              confidence: values.confidence ? Number(values.confidence) : undefined,
            });
            onClose();
          }}
        >
          {({ setFieldValue, values }) => (
            <Form>
              <DialogBody>
                <ObjectMarkingField name="objectMarking" style={fieldSpacingContainerStyle} setFieldValue={setFieldValue} />
                <ObjectLabelField name="objectLabel" style={fieldSpacingContainerStyle} setFieldValue={setFieldValue} values={values.objectLabel} />
                <ConfidenceField name="confidence" entityType="Report" containerStyle={fieldSpacingContainerStyle} />
              </DialogBody>
              <DialogFooter>
                <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
                <Button type="submit">{t_i18n('Validate')}</Button>
              </DialogFooter>
            </Form>
          )}
        </Formik>
      </DialogContent>
    </Dialog>
  );
};

export default MappingEnrichmentDialog;
