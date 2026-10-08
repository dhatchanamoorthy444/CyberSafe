export default function UrlInputForm({ onSubmit, loading }) {
  return (
    <form
      onSubmit={(e) => { e.preventDefault(); const url = e.target.url.value; if (url) onSubmit(url); }}
      className="glass-panel p-8 max-w-3xl mx-auto flex flex-col gap-4"
    >
      <h1 className="text-3xl font-bold tracking-tight">CyberSafe</h1>
      <p className="text-slate-400">Zero-Trust Real-Time Threat Intelligence</p>
      <div className="flex gap-3">
        <input
          name="url"
          type="text"
          placeholder="https://example.com"
          className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 text-white focus:outline-none focus:border-emerald-400"
        />
        <button
          type="submit"
          disabled={loading}
          className="bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold px-6 py-3 rounded-lg transition disabled:opacity-50"
        >
          {loading ? 'Scanning...' : 'Scan URL'}
        </button>
      </div>
    </form>
  );
}
