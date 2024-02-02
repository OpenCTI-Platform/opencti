export interface PublicManifestWidget {
  id: string
  layout: {
    w: number
    h: number,
    x: number
    y: number
    i: string
    moved: boolean
    static: boolean
  }
  parameters: {
    title: string
  }
  perspective: 'entities' | 'relationships' | 'audits' | null
  type: string
}

export interface PublicManifestConfig {
  startDate?: string
  endDate?: string
  relativeDate?: string
}

export interface PublicManifest {
  config?: PublicManifestConfig
  widgets?: Record<string, PublicManifestWidget>
}
