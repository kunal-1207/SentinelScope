import type { ReactNode } from 'react'
import './globals.css'

export const metadata = {
  title: 'SentinelScope - DevSecOps Security Platform',
  description: 'Comprehensive DevSecOps security automation platform',
}

export default function RootLayout({
  children,
}: {
  children: ReactNode
}) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-gray-50">
        <div className="flex flex-col min-h-screen">
          {children}
        </div>
      </body>
    </html>
  )
}