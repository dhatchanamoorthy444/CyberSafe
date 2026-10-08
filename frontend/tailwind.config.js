export default {
  content: ["./app/**/*.{js,ts,jsx,tsx,mdx}", "./components/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        slate: { 950: '#0F172A', 900: '#111827', 800: '#1E293B' },
        emerald: { 400: '#34D399', 500: '#10B981', 600: '#059669' },
        amber: { 400: '#FBBF24', 500: '#F59E0B', 600: '#D97706' },
        crimson: { 500: '#EF4444', 600: '#DC2626' },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
    },
  },
  plugins: [],
};
