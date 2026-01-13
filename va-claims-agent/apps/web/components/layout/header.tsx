'use client'

import { Bell, User, LogOut } from 'lucide-react'
import Link from 'next/link'
import { useAuth } from '@/hooks/use-auth'

export function Header() {
  const { user, logout } = useAuth()

  return (
    <header className="bg-va-blue text-white shadow-md">
      <div className="flex items-center justify-between px-6 py-4">
        <Link href="/" className="flex items-center space-x-3">
          <div className="w-10 h-10 bg-white rounded-full flex items-center justify-center">
            <span className="text-va-blue font-bold text-lg">VA</span>
          </div>
          <div>
            <h1 className="text-xl font-bold">VA Claims Agent</h1>
            <p className="text-xs text-gray-300">AI-Powered Claims Processing</p>
          </div>
        </Link>

        <div className="flex items-center space-x-4">
          <button className="p-2 hover:bg-white/10 rounded-full transition-colors">
            <Bell className="h-5 w-5" />
          </button>

          <div className="flex items-center space-x-2">
            <div className="w-8 h-8 bg-va-gold rounded-full flex items-center justify-center">
              <User className="h-5 w-5 text-va-blue" />
            </div>
            <span className="text-sm">{user?.email || 'Guest'}</span>
          </div>

          {user && (
            <button
              onClick={logout}
              className="p-2 hover:bg-white/10 rounded-full transition-colors"
              title="Logout"
            >
              <LogOut className="h-5 w-5" />
            </button>
          )}
        </div>
      </div>

      {/* Warning Banner for Initial Claims */}
      <div className="bg-va-gold text-va-blue px-6 py-2 text-sm">
        <strong>Important:</strong> Per 38 CFR 14.636, fees cannot be charged on initial claims.
        All fee agreements must comply with VA regulations.
      </div>
    </header>
  )
}
