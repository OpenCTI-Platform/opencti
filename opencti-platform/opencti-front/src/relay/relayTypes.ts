export interface RelayError {
  res: {
    errors: {
      message?: string
      name?: string
      path?: string[]
      extensions: {
        code: string
        data: {
          genre: string
          http_status: number
        }
        stacktrace?: string[]
      }
    }[]
  }
}
