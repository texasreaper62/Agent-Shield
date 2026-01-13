'use client'

import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, File, Trash2, Eye, CheckCircle, Clock, AlertCircle } from 'lucide-react'
import { documentsApi } from '@/lib/api'

const DOCUMENT_TYPES = [
  { value: 'dd214', label: 'DD214' },
  { value: 'service_treatment_record', label: 'Service Treatment Record' },
  { value: 'medical_record', label: 'Medical Record' },
  { value: 'buddy_statement', label: 'Buddy Statement' },
  { value: 'nexus_letter', label: 'Nexus Letter' },
  { value: 'dbq', label: 'DBQ' },
  { value: 'va_decision', label: 'VA Decision' },
  { value: 'other', label: 'Other' },
]

export default function DocumentsPage() {
  const queryClient = useQueryClient()
  const [dragActive, setDragActive] = useState(false)
  const [uploading, setUploading] = useState(false)

  const { data: documents, isLoading } = useQuery({
    queryKey: ['documents'],
    queryFn: () => documentsApi.list().then(r => r.data),
  })

  const uploadMutation = useMutation({
    mutationFn: ({ file, type }: { file: File; type?: string }) =>
      documentsApi.upload(file, type),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['documents'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => documentsApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['documents'] })
    },
  })

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true)
    } else if (e.type === 'dragleave') {
      setDragActive(false)
    }
  }, [])

  const handleDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setDragActive(false)

    const files = Array.from(e.dataTransfer.files)
    setUploading(true)

    for (const file of files) {
      await uploadMutation.mutateAsync({ file })
    }

    setUploading(false)
  }, [uploadMutation])

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || [])
    setUploading(true)

    for (const file of files) {
      await uploadMutation.mutateAsync({ file })
    }

    setUploading(false)
    e.target.value = ''
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'embedded':
      case 'classified':
        return <CheckCircle className="h-5 w-5 text-green-500" />
      case 'processing':
      case 'ocr_complete':
        return <Clock className="h-5 w-5 text-yellow-500" />
      case 'failed':
        return <AlertCircle className="h-5 w-5 text-red-500" />
      default:
        return <Clock className="h-5 w-5 text-gray-400" />
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Documents</h1>
        <p className="text-gray-600">Upload and manage your military and medical records</p>
      </div>

      {/* Upload Area */}
      <div
        className={`card border-2 border-dashed transition-colors ${
          dragActive ? 'border-va-blue bg-blue-50' : 'border-gray-300'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <div className="text-center py-8">
          <Upload className="mx-auto h-12 w-12 text-gray-400" />
          <p className="mt-4 text-lg font-medium">
            {uploading ? 'Uploading...' : 'Drag and drop files here'}
          </p>
          <p className="text-gray-500">or</p>
          <label className="mt-2 inline-block">
            <input
              type="file"
              multiple
              accept=".pdf,.png,.jpg,.jpeg,.tiff"
              onChange={handleFileChange}
              className="hidden"
              disabled={uploading}
            />
            <span className="btn btn-primary cursor-pointer">
              Select Files
            </span>
          </label>
          <p className="mt-2 text-sm text-gray-500">
            Supported: PDF, PNG, JPG, TIFF
          </p>
        </div>
      </div>

      {/* Documents List */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Uploaded Documents</h2>
        {isLoading ? (
          <p className="text-gray-500">Loading...</p>
        ) : documents?.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead>
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    File
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Type
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">
                    Uploaded
                  </th>
                  <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {documents.map((doc: any) => (
                  <tr key={doc.id} className="hover:bg-gray-50">
                    <td className="px-4 py-3">
                      <div className="flex items-center">
                        <File className="h-5 w-5 text-gray-400 mr-2" />
                        <span className="font-medium">{doc.original_filename}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <select
                        value={doc.document_type}
                        onChange={(e) =>
                          documentsApi.classify(doc.id, e.target.value).then(() =>
                            queryClient.invalidateQueries({ queryKey: ['documents'] })
                          )
                        }
                        className="input text-sm py-1"
                      >
                        {DOCUMENT_TYPES.map((type) => (
                          <option key={type.value} value={type.value}>
                            {type.label}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center">
                        {getStatusIcon(doc.status)}
                        <span className="ml-2 text-sm capitalize">
                          {doc.status.replace(/_/g, ' ')}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-500">
                      {new Date(doc.uploaded_at).toLocaleDateString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        onClick={() => window.open(`/api/documents/${doc.id}/download`, '_blank')}
                        className="text-va-blue hover:text-va-blue-light mr-2"
                        title="View"
                      >
                        <Eye className="h-5 w-5" />
                      </button>
                      <button
                        onClick={() => {
                          if (confirm('Delete this document?')) {
                            deleteMutation.mutate(doc.id)
                          }
                        }}
                        className="text-red-500 hover:text-red-700"
                        title="Delete"
                      >
                        <Trash2 className="h-5 w-5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="text-gray-500">No documents uploaded yet.</p>
        )}
      </div>
    </div>
  )
}
