// Error type shared by the Scan API client (lib/scanApi.ts) and the pages.
export class ApiError extends Error {
  code?: string
  status: number
  body: unknown
  constructor(message: string, status: number, code?: string, body?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.body = body
  }
}
