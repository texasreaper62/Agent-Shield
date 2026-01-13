import type { Metadata } from 'next'
import './globals.css'
import { Providers } from './providers'
import { Header } from '@/components/layout/header'
import { Sidebar } from '@/components/layout/sidebar'

export const metadata: Metadata = {
  title: 'VA Claims Agent',
  description: 'AI-powered VA disability claims processing system',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>
        <Providers>
          <div className="min-h-screen flex flex-col">
            <Header />
            <div className="flex flex-1">
              <Sidebar />
              <main className="flex-1 p-6 bg-gray-50">
                {children}
              </main>
            </div>
          </div>
        </Providers>
      </body>
    </html>
  )
}
