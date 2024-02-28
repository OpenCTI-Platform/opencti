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
    title?: string
    interval?: string
    stacked?: boolean
    legend?: boolean
    distributed?: boolean
  }
  dataSelection: {
    label?: string
    number?: number
    attribute?: string
    date_attribute?: string
    centerLat?: number
    centerLng?: number
    zoom?: number
    isTo?: boolean
  }[]
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
