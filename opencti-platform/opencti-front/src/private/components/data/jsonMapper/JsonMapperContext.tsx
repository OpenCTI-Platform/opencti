import React, { createContext, ReactNode, useContext, useState } from 'react';

interface JsonMapperContextProps {
  dynamicMappingColumn: string | null;
  setDynamicMappingColumn: (index: string) => void;
}

interface JsonMapperProviderProps {
  children: ReactNode;
}

const JsonMapperContext = createContext<JsonMapperContextProps | undefined>(undefined);
export const JsonMapperProvider: React.FC<JsonMapperProviderProps> = ({ children }) => {
  const [dynamicMappingColumn, setDynamicMappingColumn] = useState<string | null>(null);
  return (
    <JsonMapperContext.Provider value={{ dynamicMappingColumn, setDynamicMappingColumn }}>
      {children}
    </JsonMapperContext.Provider>
  );
};
export const useJsonMapperContext = () => {
  const context = useContext(JsonMapperContext);
  if (!context) {
    throw new Error('useJsonMapperContext must be used within a JsonMapperProvider');
  }
  return context;
};
