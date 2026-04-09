import React, { createContext, ReactNode, useContext, useState } from 'react';

export interface ExportTheme {
  id: string;
  name: string;
  theme_background: string;
  theme_paper: string;
  theme_nav: string;
  theme_primary: string;
  theme_secondary: string;
  theme_accent: string;
  theme_text_color: string;
  theme_logo?: string | null;
  theme_logo_collapsed?: string | null;
  theme_logo_login?: string | null;
}

interface ExportThemeContextType {
  exportTheme: ExportTheme | null;
  setExportTheme: (theme: ExportTheme | null) => void;
}

const ExportThemeContext = createContext<ExportThemeContextType>({
  exportTheme: null,
  setExportTheme: () => {},
});

export const useExportTheme = () => useContext(ExportThemeContext);

export const ExportThemeProvider = ({ children }: { children: ReactNode }) => {
  const [exportTheme, setExportTheme] = useState<ExportTheme | null>(null);
  return (
    <ExportThemeContext.Provider value={{ exportTheme, setExportTheme }}>
      {children}
    </ExportThemeContext.Provider>
  );
};

export default ExportThemeContext;
