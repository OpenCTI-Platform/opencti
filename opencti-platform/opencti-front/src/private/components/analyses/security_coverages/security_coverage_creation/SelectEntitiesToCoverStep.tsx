import DataTable from 'src/components/dataGrid/DataTable';
import { DATA_COLUMNS } from './SecurityCoverageCreation';

// TODO :
// get type of covered entity to apply correct filters
// Build filters
// Write query
// Fill DataTable
// Manage select all option
// Add a button for next step
// change add_related_entities with entities_to_add and add_all_related_entities in finalValues

const SelectEntitiesToCoverStep = () => {
  return (
    <DataTable />
  );
};

export default SelectEntitiesToCoverStep;
