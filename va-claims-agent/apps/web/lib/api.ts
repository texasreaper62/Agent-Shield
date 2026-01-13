import axios from 'axios'

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

export const api = axios.create({
  baseURL: `${API_URL}/api`,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = typeof window !== 'undefined' ? localStorage.getItem('token') : null
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Handle auth errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Redirect to login
      if (typeof window !== 'undefined') {
        localStorage.removeItem('token')
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

// API functions
export const authApi = {
  login: (email: string, password: string) =>
    api.post('/auth/token', new URLSearchParams({ username: email, password }), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    }),
  register: (data: { email: string; password: string; first_name?: string; last_name?: string }) =>
    api.post('/auth/register', data),
  me: () => api.get('/auth/me'),
}

export const veteransApi = {
  getProfile: () => api.get('/veterans/me'),
  createProfile: (data: any) => api.post('/veterans', data),
  updateProfile: (data: any) => api.put('/veterans/me', data),
}

export const documentsApi = {
  list: (params?: any) => api.get('/documents', { params }),
  get: (id: string) => api.get(`/documents/${id}`),
  upload: (file: File, documentType?: string) => {
    const formData = new FormData()
    formData.append('file', file)
    if (documentType) formData.append('document_type', documentType)
    return api.post('/documents/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
  classify: (id: string, documentType: string) =>
    api.put(`/documents/${id}/classify`, { document_type: documentType }),
  delete: (id: string) => api.delete(`/documents/${id}`),
}

export const claimsApi = {
  list: (params?: any) => api.get('/claims', { params }),
  get: (id: string) => api.get(`/claims/${id}`),
  create: (data: any) => api.post('/claims', data),
  analyze: (id: string) => api.post(`/claims/${id}/analyze`),
  updateStatus: (id: string, status: string) => api.put(`/claims/${id}/status`, null, { params: { new_status: status } }),
  addCondition: (id: string, data: any) => api.post(`/claims/${id}/conditions`, data),
}

export const evidenceApi = {
  list: (claimId: string, params?: any) => api.get(`/evidence/claim/${claimId}`, { params }),
  get: (id: string) => api.get(`/evidence/${id}`),
  create: (data: any) => api.post('/evidence', data),
  addCitation: (id: string, data: any) => api.post(`/evidence/${id}/citations`, data),
}

export const formsApi = {
  supported: () => api.get('/forms/supported'),
  listForClaim: (claimId: string) => api.get(`/forms/claim/${claimId}`),
  get: (id: string) => api.get(`/forms/${id}`),
  create: (data: any) => api.post('/forms', data),
  updateFields: (id: string, updates: any[]) => api.put(`/forms/${id}/fields`, updates),
  regenerate: (id: string) => api.post(`/forms/${id}/regenerate`),
  download: (id: string) => api.get(`/forms/${id}/download`),
}

export const reviewsApi = {
  listPending: () => api.get('/reviews/pending'),
  listForClaim: (claimId: string) => api.get(`/reviews/claim/${claimId}`),
  get: (id: string) => api.get(`/reviews/${id}`),
  create: (data: any) => api.post('/reviews', data),
  start: (id: string) => api.put(`/reviews/${id}/start`),
  complete: (id: string, decision: string, summary?: string, rationale?: string) =>
    api.put(`/reviews/${id}/complete`, null, { params: { decision, summary, rationale } }),
  updateChecklist: (id: string, checklist: any[]) => api.put(`/reviews/${id}/checklist`, checklist),
  addComment: (id: string, data: any) => api.post(`/reviews/${id}/comments`, data),
}

export const submissionsApi = {
  listPending: () => api.get('/submissions/pending'),
  get: (id: string) => api.get(`/submissions/${id}`),
  create: (claimId: string) => api.post('/submissions', { claim_id: claimId }),
  approve: (id: string, notes?: string) => api.post(`/submissions/${id}/approve`, { notes }),
  submit: (id: string) => api.post(`/submissions/${id}/submit`),
  checkStatus: (id: string) => api.get(`/submissions/${id}/status`),
}

export const knowledgeApi = {
  search: (query: string, category?: string) => api.get('/knowledge/search', { params: { query, category } }),
  listArticles: (params?: any) => api.get('/knowledge/articles', { params }),
  getArticle: (slug: string) => api.get(`/knowledge/articles/${slug}`),
  listCFR: (params?: any) => api.get('/knowledge/cfr', { params }),
  getCFRSection: (section: string) => api.get(`/knowledge/cfr/${section}`),
  getDiagnosticCode: (dc: string) => api.get(`/knowledge/diagnostic-codes/${dc}`),
  searchConditions: (query: string) => api.get('/knowledge/conditions/search', { params: { query } }),
}
