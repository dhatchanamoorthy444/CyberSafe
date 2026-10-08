export default function SandboxViewer({ sandbox }) {
  return (
    <div className="glass-panel p-6 flex flex-col gap-3">
      <h3 className="text-lg font-semibold">Sandbox Proof</h3>
      <div className="bg-slate-950 rounded-lg p-2 border border-slate-700">
        {sandbox?.screenshot_b64 ? (
          <img src={`data:image/png;base64,${sandbox.screenshot_b64}`} alt="sandbox" className="w-full rounded" />
        ) : (
          <div className="h-48 flex items-center justify-center text-slate-500">No screenshot available</div>
        )}
      </div>
      <div className="text-sm space-y-1 text-slate-300 font-mono">
        <p><strong>Page Title:</strong> {sandbox?.page_title || 'N/A'}</p>
        <p><strong>Final URL:</strong> {sandbox?.final_url || 'N/A'}</p>
        <p><strong>Login Form:</strong> {sandbox?.has_login_form ? 'Yes (warning)' : 'No'}</p>
      </div>
    </div>
  );
}
