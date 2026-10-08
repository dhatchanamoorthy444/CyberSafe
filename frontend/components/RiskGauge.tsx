export default function RiskGauge({ score }) {
  const color = score < 30 ? 'text-emerald-400' : score < 70 ? 'text-amber-400' : 'text-crimson-500';
  const label = score < 30 ? 'SAFE' : score < 70 ? 'SUSPICIOUS' : 'MALICIOUS';
  return (
    <div className="glass-panel p-6 flex flex-col gap-2">
      <h3 className="text-lg font-semibold">Risk Score</h3>
      <div className={`text-7xl font-mono font-bold ${color}`}>{score}</div>
      <div className={`text-xl font-bold uppercase tracking-widest ${color}`}>{label}</div>
      <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden mt-2">
        <div className={`h-full rounded-full ${score < 30 ? 'bg-emerald-400' : score < 70 ? 'bg-amber-400' : 'bg-crimson-500'}`} style={{ width: `${score}%` }} />
      </div>
    </div>
  );
}
