import React, { createContext, ReactNode, useContext, useState } from 'react';

interface CsvMapperContextProps {
  columnIndex: string | null;
  setColumnIndex: (index: string) => void;
}

interface CsvMapperProviderProps {
  children: ReactNode;
}

const CsvMapperContext = createContext<CsvMapperContextProps | undefined>(undefined);

export const CsvMapperProvider: React.FC<CsvMapperProviderProps> = ({ children }) => {
  const [columnIndex, setColumnIndex] = useState<string | null>(null);

  return (
    <CsvMapperContext.Provider value={{ columnIndex, setColumnIndex }}>
      {children}
    </CsvMapperContext.Provider>
  );
};

export const useCsvMapperContext = () => {
  const context = useContext(CsvMapperContext);
  if (!context) {
    throw new Error('useCsvMapperContext must be used within a CsvMapperProvider');
  }
  return context;
};
