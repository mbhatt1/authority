import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

export default withMermaid(defineConfig({
  title: 'Authority',
  titleTemplate: ':title | Authority',
  description: 'Capability-based security unikernel: cryptographic capabilities, tamper-evident audit, and resource budgets',
  lang: 'en-US',

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
    ['meta', { charset: 'utf-8' }],
    ['meta', { name: 'viewport', content: 'width=device-width, initial-scale=1.0' }],
    ['meta', { name: 'theme-color', content: '#dc2626' }],

    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'Authority' }],
    ['meta', { property: 'og:description', content: 'Capability-based security unikernel' }],
    ['meta', { property: 'og:url', content: 'https://authority-nanos.dev' }],

    ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
    ['meta', { name: 'twitter:title', content: 'Authority' }],
    ['meta', { name: 'twitter:description', content: 'Capability-based security unikernel' }],
  ],

  markdown: {
    theme: {
      light: 'github-light',
      dark: 'github-dark',
    },
    lineNumbers: true,
  },

  cleanUrls: true,
  lastUpdated: true,
  ignoreDeadLinks: true,

  themeConfig: {
    logo: '/logo.svg',
    siteTitle: 'Authority',

    nav: [
      { text: 'Home', link: '/' },
      {
        text: 'Getting Started',
        items: [
          { text: 'Overview', link: '/getting-started/' },
          { text: 'Installation', link: '/getting-started/installation' },
          { text: 'First Program', link: '/getting-started/first-agent' }
        ]
      },
      {
        text: 'Project',
        items: [
          { text: 'Charter', link: '/guide/charter' },
          { text: 'Roadmap', link: '/guide/roadmap' },
          { text: 'Contributing', link: '/guide/contributing' },
          { text: 'Release Notes', link: '/guide/release-notes' }
        ]
      },
      {
        text: 'Reference',
        items: [
          { text: 'Architecture', link: '/architecture/' },
          { text: 'Security', link: '/security/' },
          { text: 'Policy', link: '/policy/' },
          { text: 'API', link: '/api/' }
        ]
      },
      {
        text: 'Design',
        items: [
          { text: 'Overview', link: '/design/' },
          { text: 'Kernel Design', link: '/design/ak-design' },
          { text: 'Base Contract', link: '/design/ak-base-contract' },
          { text: 'Invariants', link: '/design/invariants' },
          { text: 'Threat Model', link: '/design/ak-threat-model' }
        ]
      },
      {
        text: 'Development',
        items: [
          { text: 'Testing', link: '/testing/' },
          { text: 'Tools', link: '/tools/' },
          { text: 'Bugs & Issues', link: '/design/bug-checklist' }
        ]
      },
      { text: 'FAQ', link: '/faq' }
    ],

    sidebar: {
      '/getting-started/': [
        {
          text: 'Getting Started',
          items: [
            { text: 'Quick Start', link: '/getting-started/' },
            { text: 'Installation', link: '/getting-started/installation' },
            { text: 'First Program', link: '/getting-started/first-agent' }
          ]
        }
      ],
      '/guide/': [
        {
          text: 'Project Guide',
          items: [
            { text: 'Overview', link: '/guide/' },
            { text: 'Charter', link: '/guide/charter' },
            { text: 'Roadmap', link: '/guide/roadmap' },
            { text: 'Contributing', link: '/guide/contributing' },
            { text: 'Release Notes', link: '/guide/release-notes' }
          ]
        }
      ],
      '/architecture/': [
        {
          text: 'Architecture',
          items: [
            { text: 'Overview', link: '/architecture/' },
            { text: 'Fork Relationship', link: '/architecture/nanos-fork' },
            { text: 'Authority Kernel', link: '/architecture/authority-kernel' }
          ]
        }
      ],
      '/design/': [
        {
          text: 'Design & Specifications',
          items: [
            { text: 'Overview', link: '/design/' },
            { text: 'Kernel Design', link: '/design/ak-design' },
            { text: 'Base Contract', link: '/design/ak-base-contract' },
            { text: 'Roadmap', link: '/design/ak-roadmap' },
            { text: 'Security Invariants', link: '/design/invariants' },
            { text: 'Threat Model', link: '/design/ak-threat-model' },
            { text: 'Authority Kernel', link: '/design/agentic-kernel' },
            { text: 'Bug Checklist', link: '/design/bug-checklist' }
          ]
        }
      ],
      '/security/': [
        {
          text: 'Security',
          items: [
            { text: 'Overview', link: '/security/' },
            { text: 'Security Invariants', link: '/security/invariants' },
            { text: 'Threat Model', link: '/security/threat-model' }
          ]
        }
      ],
      '/policy/': [
        {
          text: 'Policy',
          items: [
            { text: 'Overview', link: '/policy/' },
            { text: 'JSON Format', link: '/policy/json-format' },
            { text: 'TOML Format', link: '/policy/toml-format' }
          ]
        }
      ],
      '/api/': [
        {
          text: 'API Reference',
          items: [
            { text: 'Overview', link: '/api/' },
            { text: 'Syscalls', link: '/api/syscalls' },
            { text: 'Effects', link: '/api/effects' }
          ]
        }
      ],
      '/testing/': [
        {
          text: 'Testing',
          items: [
            { text: 'Overview', link: '/testing/' },
            { text: 'Fuzz Testing', link: '/testing/fuzz-testing' },
            { text: 'Runtime Testing', link: '/testing/runtime-testing' }
          ]
        }
      ],
      '/tools/': [
        {
          text: 'Tools & Utilities',
          items: [
            { text: 'Overview', link: '/tools/' },
            { text: 'Trace Utilities', link: '/tools/trace-utilities' },
            { text: 'Build Scripts', link: '/tools/scripts' }
          ]
        }
      ]
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/nanovms/authority-nanos' }
    ],

    footer: {
      message: 'Apache 2.0 License',
      copyright: 'Copyright © 2024-present NanoVMs, Inc.'
    },

    search: {
      provider: 'local'
    },

    editLink: {
      pattern: 'https://github.com/nanovms/authority-nanos/edit/master/docs/:path',
      text: 'Edit on GitHub'
    }
  },
  mermaid: {
    theme: 'default'
  },
  mermaidPlugin: {
    class: 'mermaid'
  }
}))
