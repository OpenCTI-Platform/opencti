import makeStyles from '@mui/styles/makeStyles';
import type { Theme } from '../../../../components/Theme';

// Shared styles consumed by FormSchemaEditor.tsx and its extracted section components
// (MainEntitySection, AdditionalEntitiesSection, RelationshipsSection, useFieldRenderer).
// Every class below is used, just from sibling files, which custom-rules/classes-rule's
// same-file "classes.<key>" usage check cannot see across module boundaries.
/* eslint-disable custom-rules/classes-rule */
const useStyles = makeStyles<Theme>(() => ({
  container: {
    marginTop: 20,
  },
  tabPanel: {
    marginTop: 20,
  },
  entitySection: {
    padding: 20,
    border: '1px solid var(--border-elevation-subtle)',
    borderRadius: 4,
  },
  entityHeader: {
    display: 'flex',
    justifyContent: 'space-between',
  },
  fieldGroup: {
    padding: 15,
    borderRadius: 4,
    border: '1px solid var(--border-elevation-subtle)',
  },
  fieldHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  fieldTitle: {
    fontWeight: 600,
    fontSize: 14,
  },
  relationshipGroup: {
    padding: 15,
    borderRadius: 4,
    border: '1px solid var(--border-elevation-subtle)',
  },
  addButton: {
    marginTop: 10,
  },
  alert: {
    marginBottom: 20,
  },
}));

export default useStyles;
