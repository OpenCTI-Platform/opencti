import { useState } from 'react';

// export interface ExportContextType {
//   selected_ids?: string[],
//   options?: any,
//   type?: string,
//   elementId?: string | null,
//   edges?: any,
// }

interface UseExportProps<T> {
  options?: any;
  type?: string;
  elementId?: string | null;
  selectedElements?: Record<string, T>,
}

const useExport = <T extends { id: string }, E extends { node: { id: string } }>(
  {
    type,
    selectedElements,
  }: UseExportProps<T>,
) => {
  const [edges, setEdges] = useState<E[]>([]);

  const selectedElementsIds = selectedElements ? Object.keys(selectedElements) : [];
  const queryIds = edges.map((o) => o.node.id);
  const selected_ids = queryIds.filter((id) => selectedElementsIds.includes(id));

  return {
    setEdges,
    edges,
    selected_ids,
    type,
  };
};

// const defaultContext = {
//   selected_ids: [],
//   options: {},
//   type: undefined,
//   elementId: undefined,
//   edges: undefined,
// };
// export const ExportContext = React.createContext<ExportContextType>(defaultContext);
//
// const useExport = () => {
//   const { selected_ids, options, type, elementId } = useContext(ExportContext);
//   if (!selected_ids || !options || !type) {
//     throw new Error('Invalid export context !');
//   }
//   return { selected_ids, options, type, elementId };
// };

export default useExport;
