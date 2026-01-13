'use client'

import { useQuery } from '@tanstack/react-query'
import Link from 'next/link'
import { Plus, ChevronRight } from 'lucide-react'
import { claimsApi } from '@/lib/api'

export default function ClaimsPage() {
  const { data: claims, isLoading } = useQuery({
    queryKey: ['claims'],
    queryFn: () => claimsApi.list().then(r => r.data),
  })

  const getStatusColor = (status: string) => {
    const colors: Record<string, string> = {
      draft: 'bg-gray-100 text-gray-700',
      evidence_gathering: 'bg-blue-100 text-blue-700',
      analysis_pending: 'bg-yellow-100 text-yellow-700',
      analysis_complete: 'bg-green-100 text-green-700',
      review_pending: 'bg-orange-100 text-orange-700',
      approved: 'bg-emerald-100 text-emerald-700',
      rejected: 'bg-red-100 text-red-700',
      submitted: 'bg-purple-100 text-purple-700',
    }
    return colors[status] || 'bg-gray-100 text-gray-700'
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Claims</h1>
          <p className="text-gray-600">Manage your VA disability claims</p>
        </div>
        <Link href="/claims/new" className="btn btn-primary flex items-center">
          <Plus className="h-5 w-5 mr-2" />
          New Claim
        </Link>
      </div>

      {isLoading ? (
        <div className="card">
          <p className="text-gray-500">Loading claims...</p>
        </div>
      ) : claims?.length > 0 ? (
        <div className="space-y-4">
          {claims.map((claim: any) => (
            <Link
              key={claim.id}
              href={`/claims/${claim.id}`}
              className="card block hover:shadow-lg transition-shadow"
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3">
                    <h3 className="text-lg font-semibold">
                      {claim.conditions?.length > 0
                        ? claim.conditions.map((c: any) => c.condition_name).join(', ')
                        : 'Untitled Claim'}
                    </h3>
                    <span className={`badge ${getStatusColor(claim.status)}`}>
                      {claim.status.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <p className="text-gray-500 mt-1">
                    {claim.claim_type.charAt(0).toUpperCase() + claim.claim_type.slice(1)} Claim
                    {' '}({claim.conditions?.length || 0} conditions)
                  </p>
                  <div className="flex items-center mt-2 text-sm text-gray-500">
                    <span>Created: {new Date(claim.created_at).toLocaleDateString()}</span>
                    {claim.confidence_score && (
                      <span className="ml-4">
                        Strength: {Math.round(claim.confidence_score * 100)}%
                      </span>
                    )}
                  </div>
                </div>
                <ChevronRight className="h-6 w-6 text-gray-400" />
              </div>
            </Link>
          ))}
        </div>
      ) : (
        <div className="card text-center py-12">
          <h3 className="text-lg font-medium text-gray-900">No claims yet</h3>
          <p className="text-gray-500 mt-2">
            Upload your documents first, then start a new claim.
          </p>
          <div className="mt-4 space-x-4">
            <Link href="/documents" className="btn btn-secondary">
              Upload Documents
            </Link>
            <Link href="/claims/new" className="btn btn-primary">
              Start New Claim
            </Link>
          </div>
        </div>
      )}
    </div>
  )
}
