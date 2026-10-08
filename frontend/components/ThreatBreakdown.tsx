export default function ThreatBreakdown({ threats }) {
  return (
    <div className="glass-panel p-6">
      <h3 className="text-lg font-semibold mb-3">Detected Threats</h3>
      <ul className="list-disc list-inside text-slate-300 space-y-1">
        {threats.map((t, i) => (
          <li key={i} className="text-amber-400">{t}</li>
        ))}
      </ul>
      {threats.length === 0 && <p className="text-emerald-400">No threats detected.</p>}
    </div>
  );
}
