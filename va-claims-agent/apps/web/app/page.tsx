'use client'

import { useQuery } from '@tanstack/react-query'
import { FileText, Upload, CheckCircle, Clock, AlertCircle } from 'lucide-react'
import Link from 'next/link'
import { api } from '@/lib/api'

export default function Dashboard() {
  const { data: claims, isLoading: claimsLoading } = useQuery({
    queryKey: ['claims'],
    queryFn: () => api.get('/claims').then(r => r.data),
  })

  const { data: documents, isLoading: docsLoading } = useQuery({
    queryKey: ['documents'],
    queryFn: () => api.get('/documents').then(r => r.data),
  })

  const stats = [
    {
      name: 'Active Claims',
      value: claims?.filter((c: any) => !['submitted', 'va_decided'].includes(c.status)).length || 0,
      icon: FileText,
      color: 'text-blue-600',
      bg: 'bg-blue-100',
    },
    {
      name: 'Documents Uploaded',
      value: documents?.length || 0,
      icon: Upload,
      color: 'text-green-600',
      bg: 'bg-green-100',
    },
    {
      name: 'Pending Review',
      value: claims?.filter((c: any) => c.status === 'review_pending').length || 0,
      icon: Clock,
      color: 'text-yellow-600',
      bg: 'bg-yellow-100',
    },
    {
      name: 'Submitted',
      value: claims?.filter((c: any) => c.status === 'submitted').length || 0,
      icon: CheckCircle,
      color: 'text-emerald-600',
      bg: 'bg-emerald-100',
    },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-600">Welcome to the VA Claims Agent</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat) => (
          <div key={stat.name} className="card">
            <div className="flex items-center">
              <div className={`p-3 rounded-full ${stat.bg}`}>
                <stat.icon className={`h-6 w-6 ${stat.color}`} />
              </div>
              <div className="ml-4">
                <p className="text-sm font-medium text-gray-500">{stat.name}</p>
                <p className="text-2xl font-semibold text-gray-900">
                  {claimsLoading || docsLoading ? '...' : stat.value}
                </p>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Quick Actions */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Link
            href="/documents/upload"
            className="flex items-center p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
          >
            <Upload className="h-8 w-8 text-va-blue" />
            <div className="ml-4">
              <p className="font-medium">Upload Documents</p>
              <p className="text-sm text-gray-500">Add medical or military records</p>
            </div>
          </Link>
          <Link
            href="/claims/new"
            className="flex items-center p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
          >
            <FileText className="h-8 w-8 text-va-blue" />
            <div className="ml-4">
              <p className="font-medium">Start New Claim</p>
              <p className="text-sm text-gray-500">Begin a disability claim</p>
            </div>
          </Link>
          <Link
            href="/knowledge"
            className="flex items-center p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors"
          >
            <AlertCircle className="h-8 w-8 text-va-blue" />
            <div className="ml-4">
              <p className="font-medium">Knowledge Base</p>
              <p className="text-sm text-gray-500">Search 38 CFR & guidance</p>
            </div>
          </Link>
        </div>
      </div>

      {/* Recent Claims */}
      <div className="card">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-semibold">Recent Claims</h2>
          <Link href="/claims" className="text-va-blue-light hover:underline text-sm">
            View all
          </Link>
        </div>
        {claimsLoading ? (
          <p className="text-gray-500">Loading...</p>
        ) : claims?.length > 0 ? (
          <div className="space-y-3">
            {claims.slice(0, 5).map((claim: any) => (
              <Link
                key={claim.id}
                href={`/claims/${claim.id}`}
                className="flex items-center justify-between p-3 bg-gray-50 rounded hover:bg-gray-100"
              >
                <div>
                  <p className="font-medium">
                    {claim.conditions?.map((c: any) => c.condition_name).join(', ') || 'Untitled Claim'}
                  </p>
                  <p className="text-sm text-gray-500">
                    {claim.claim_type} - Created {new Date(claim.created_at).toLocaleDateString()}
                  </p>
                </div>
                <StatusBadge status={claim.status} />
              </Link>
            ))}
          </div>
        ) : (
          <p className="text-gray-500">No claims yet. Start by uploading documents.</p>
        )}
      </div>
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const statusConfig: Record<string, { label: string; className: string }> = {
    draft: { label: 'Draft', className: 'badge badge-info' },
    evidence_gathering: { label: 'Gathering Evidence', className: 'badge badge-info' },
    analysis_pending: { label: 'Analyzing', className: 'badge badge-warning' },
    analysis_complete: { label: 'Analyzed', className: 'badge badge-success' },
    review_pending: { label: 'Pending Review', className: 'badge badge-warning' },
    approved: { label: 'Approved', className: 'badge badge-success' },
    rejected: { label: 'Rejected', className: 'badge badge-error' },
    submitted: { label: 'Submitted to VA', className: 'badge badge-success' },
    va_pending: { label: 'VA Processing', className: 'badge badge-warning' },
    va_decided: { label: 'VA Decided', className: 'badge badge-info' },
  }

  const config = statusConfig[status] || { label: status, className: 'badge' }

  return <span className={config.className}>{config.label}</span>
}
