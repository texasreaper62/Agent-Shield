'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  Home,
  FileText,
  Upload,
  Search,
  ClipboardCheck,
  Send,
  BookOpen,
  Settings,
  Users,
} from 'lucide-react'
import { useAuth } from '@/hooks/use-auth'
import { clsx } from 'clsx'

const navigation = [
  { name: 'Dashboard', href: '/', icon: Home },
  { name: 'Documents', href: '/documents', icon: Upload },
  { name: 'Claims', href: '/claims', icon: FileText },
  { name: 'Evidence', href: '/evidence', icon: Search },
  { name: 'Forms', href: '/forms', icon: ClipboardCheck },
  { name: 'Submissions', href: '/submissions', icon: Send },
  { name: 'Knowledge Base', href: '/knowledge', icon: BookOpen },
]

const adminNavigation = [
  { name: 'Reviews', href: '/reviews', icon: ClipboardCheck },
  { name: 'All Veterans', href: '/veterans', icon: Users },
  { name: 'Settings', href: '/settings', icon: Settings },
]

export function Sidebar() {
  const pathname = usePathname()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin' || user?.role === 'attorney'

  return (
    <aside className="w-64 bg-white shadow-md min-h-[calc(100vh-120px)]">
      <nav className="p-4 space-y-1">
        {navigation.map((item) => {
          const isActive = pathname === item.href || pathname.startsWith(item.href + '/')
          return (
            <Link
              key={item.name}
              href={item.href}
              className={clsx(
                'flex items-center px-4 py-3 rounded-lg transition-colors',
                isActive
                  ? 'bg-va-blue text-white'
                  : 'text-gray-700 hover:bg-gray-100'
              )}
            >
              <item.icon className="h-5 w-5 mr-3" />
              {item.name}
            </Link>
          )
        })}

        {isAdmin && (
          <>
            <div className="pt-4 pb-2">
              <p className="px-4 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                Administration
              </p>
            </div>
            {adminNavigation.map((item) => {
              const isActive = pathname === item.href || pathname.startsWith(item.href + '/')
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  className={clsx(
                    'flex items-center px-4 py-3 rounded-lg transition-colors',
                    isActive
                      ? 'bg-va-blue text-white'
                      : 'text-gray-700 hover:bg-gray-100'
                  )}
                >
                  <item.icon className="h-5 w-5 mr-3" />
                  {item.name}
                </Link>
              )
            })}
          </>
        )}
      </nav>

      {/* Help Section */}
      <div className="p-4 mt-auto">
        <div className="bg-gray-100 rounded-lg p-4">
          <h3 className="font-semibold text-sm">Need Help?</h3>
          <p className="text-xs text-gray-600 mt-1">
            Access our knowledge base for guidance on VA claims and 38 CFR regulations.
          </p>
          <Link
            href="/knowledge"
            className="text-va-blue-light text-sm hover:underline mt-2 inline-block"
          >
            Browse Knowledge Base
          </Link>
        </div>
      </div>
    </aside>
  )
}
