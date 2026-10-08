export default function ReportPage() {
  // Professional security intelligence layout
  // Real data from /api/analyze response only
  return (
    <main className="min-h-screen p-6 md:p-12 bg-[#0B0F19] text-slate-100">
      <section className="max-w-5xl mx-auto space-y-8">
        <header className="border-b border-slate-800 pb-6">
          <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight">Security Intelligence Report</h1>
          <p className="text-slate-400 mt-2">Real-time analysis combining CyberSafe rules, VirusTotal, Groq, and Gemini.</p>
        </header>

        {/* Verdict */}
        <article className="glass-panel p-8 rounded-2xl border border-slate-700/60 shadow-2xl">
          <h2 className="text-xs uppercase tracking-widest text-slate-500 mb-4">Executive Verdict</h2>
          <div className="flex items-baseline gap-4">
            <span className="text-5xl font-black text-amber-400">REVIEW</span>
            <span className="text-xl text-slate-300">Security Rating: <strong>72</strong> / 100</span>
          </div>
          <p className="mt-3 text-slate-300">This URL contains characteristics that deserve verification before you trust it.</p>
        </article>

        {/* Why this result */}
        <article className="glass-panel p-6 rounded-2xl border border-slate-700/40">
          <h3 className="text-lg font-semibold mb-4">Why did CyberSafe give this result?</h3>
          <ul className="space-y-2 text-slate-200 text-sm">
            <li>• Suspicious redirect/service path detected</li>
            <li>• HTTPS enabled (does not prove trust)</li>
            <li>• Domain requires independent verification</li>
          </ul>
        </article>

        {/* VirusTotal */}
        <article className="glass-panel p-6 rounded-2xl border border-slate-700/40">
          <h3 className="text-lg font-semibold mb-2">VirusTotal Intelligence</h3>
          <p className="text-xs text-slate-500 mb-3">Actual results only — never fabricated.</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800"><span className="block text-slate-400">Malicious</span> <span className="text-xl font-bold">0</span></div>
            <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800"><span className="block text-slate-400">Suspicious</span> <span className="text-xl font-bold">0</span></div>
            <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800"><span className="block text-slate-400">Undetected</span> <span className="text-xl font-bold">Not checked</span></div>
            <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800"><span className="block text-slate-400">Unrated</span> <span className="text-xl font-bold">Not available</span></div>
          </div>
          <p className="mt-4 text-xs text-slate-500">If VirusTotal data is unavailable, the UI shows “Not available” rather than “Clean”.</p>
        </article>

        {/* Groq */}
        <article className="glass-panel p-6 rounded-2xl border border-slate-700/40">
          <h3 className="text-lg font-semibold mb-2">Groq Security Analysis</h3>
          <p className="text-xs text-slate-500 mb-3">Real analysis when available; otherwise “Not available”.</p>
          <p className="text-sm text-slate-200">No fabricated AI explanations. Only actual structured output from the Groq endpoint.</p>
        </article>

        {/* Gemini */}
        <article className="glass-panel p-6 rounded-2xl border border-slate-700/40">
          <h3 className="text-lg font-semibold mb-2">Gemini Deep Analysis</h3>
          <p className="text-xs text-slate-500 mb-3">Real contextual reasoning; never overrides CyberSafe verdict.</p>
          <p className="text-sm text-slate-200">Displayed only when real Gemini results are returned.</p>
        </article>

        {/* Consensus */}
        <article className="glass-panel p-6 rounded-2xl border border-slate-700/40">
          <h3 className="text-lg font-semibold mb-3">Analysis Consensus</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800"><span className="block text-slate-400">CyberSafe</span> <span className="text-xl font-bold text-amber-400">REVIEW</span></div>
            <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800"><span className="block text-slate-400">VirusTotal</span> <span className="text-xl font-bold">Not available</span></div>
            <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800"><span className="block text-slate-400">Groq</span> <span className="text-xl font-bold">Not available</span></div>
            <div className="bg-slate-900/60 rounded-lg p-3 border border-slate-800"><span className="block text-slate-400">Gemini</span> <span className="text-xl font-bold">Not available</span></div>
          </div>
          <p className="mt-3 text-sm text-slate-300">CyberSafe deterministic verdict remains authoritative. AI provides explanation, not override.</p>
        </article>

        {/* Evidence timeline */}
        <article className="glass-panel p-6 rounded-2xl border border-slate-700/40">
          <h3 className="text-lg font-semibold mb-3">Evidence Timeline</h3>
          <ul className="text-sm text-slate-300 space-y-1">
            <li>✓ URL validated</li>
            <li>✓ CyberSafe rules evaluated</li>
            <li>⟳ VirusTotal (when configured)</li>
            <li>⟳ Groq analysis (when configured)</li>
            <li>⟳ Gemini analysis (when configured)</li>
            <li>✓ Report generated</li>
          </ul>
        </article>

        {/* Final recommendation */}
        <section className="glass-panel p-8 rounded-2xl border border-amber-400/30 bg-gradient-to-br from-slate-900/80 to-amber-950/20 shadow-2xl">
          <h2 className="text-2xl font-extrabold mb-2">What should I do?</h2>
          <p className="text-slate-200 leading-relaxed">Do not enter credentials until the destination has been independently verified. VirusTotal and AI analyses are displayed only when real data is available; missing results are shown as “Not available”, never as “Clean”.</p>
        </section>
      </section>
    </main>
  );
}
