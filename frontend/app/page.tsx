"use client";
import { useState } from "react";
import UrlInputForm from "../components/UrlInputForm";
import RiskGauge from "../components/RiskGauge";
import ThreatBreakdown from "../components/ThreatBreakdown";
import SandboxViewer from "../components/SandboxViewer";

export default function Home() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleScan(url) {
    setLoading(true);
    try {
      const res = await fetch("http://localhost:8000/api/v1/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const json = await res.json();
      setData(json);
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="min-h-screen p-8 flex flex-col gap-8 max-w-6xl mx-auto">
      <UrlInputForm onSubmit={handleScan} loading={loading} />
      {data && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <RiskGauge score={data.risk_score} />
          <ThreatBreakdown threats={data.detected_threats} />
          <SandboxViewer sandbox={data.sandbox} />
        </div>
      )}
    </main>
  );
}
