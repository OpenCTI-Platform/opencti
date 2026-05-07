import VisuallyHiddenInput from '../../../private/components/common/VisuallyHiddenInput';
import useDashboardImport from './useDashboardImport';

const DashboardHiddenImportInput = ({ helpers }: { helpers: ReturnType<typeof useDashboardImport> }) => {
  return <VisuallyHiddenInput type="file" accept="application/JSON" ref={helpers.inputRef} onChange={helpers.onChange} />;
};

export default DashboardHiddenImportInput;
