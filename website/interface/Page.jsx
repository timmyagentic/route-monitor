import React, { useState } from "react";
import {
  GitCompareArrows,
  FileCheck2,
  Radio,
  ArrowDownToLine,
} from "lucide-react";
import { Action, Choices, Figure } from "./ui.jsx";
export const site = {
  name: "Route Monitor",
  lang: "zh",
  nav: [
    ["观察台", "#preview"],
    ["处理流程", "#features"],
    ["安装", "#start"],
    ["常见问题", "#limits"],
  ],
};
const steps = [
  {
    id: "direct",
    label: "直连",
    icon: Radio,
    path: "DIRECT",
    status: "两次失败",
    body: "同一目标的两次直连探测都失败，记录超时和测试时间。",
    src: "/assets/case-paths.webp",
    original: "/assets/correction-scheduling-evidence.jpg",
    width: 490,
    height: 234,
  },
  {
    id: "compare",
    label: "代理对照",
    icon: GitCompareArrows,
    path: "JP / HK",
    status: "HTTP 200",
    body: "JP、HK 出口各返回两次 HTTP 200。可以对照相同目标在不同出口上的结果。",
    src: "/assets/case-paths.webp",
    original: "/assets/correction-scheduling-evidence.jpg",
    width: 490,
    height: 234,
  },
  {
    id: "verify",
    label: "调整后复验",
    icon: FileCheck2,
    path: "复验记录",
    status: "仍未通过",
    body: "调整之后，单独复验仍未通过。原记录保留了探测和复验各自的结果。",
    src: "/assets/correction-scheduling-evidence.jpg",
    width: 1265,
    height: 712,
  },
];
export function Hero() {
  const [step, setStep] = useState("direct");
  return (
    <section className="pi-hero route-hero" aria-labelledby="hero-title">
      <div className="pi-container route-sheet">
        <header className="route-heading">
          <div>
            <h1 id="hero-title">Route Monitor</h1>
            <p>在 Mac 上复查连接使用的出口，保留每次探测和调整的结果。</p>
          </div>
          <Action href="/download" icon={ArrowDownToLine}>
            下载 macOS 版
          </Action>
        </header>
        <article className="route-log">
          <div className="route-log-title">
            <h2>出口复验记录</h2>
            <small>历史样例</small>
          </div>
          <ol className="route-path" aria-label="本次记录摘要">
            {steps.map((s) => (
              <li key={s.id}>
                <span>{s.path}</span>
                <strong>{s.status}</strong>
              </li>
            ))}
          </ol>
          <Choices
            label="选择复验阶段"
            tabs={steps}
            value={step}
            onChange={setStep}
          >
            {(item) => (
              <div className="route-case-grid">
                <div className="route-receipt">
                  <h3>{item.label}</h3>
                  <p>{item.body}</p>
                  <a href={item.original || item.src}>查看原始记录</a>
                </div>
                <Figure
                  src={item.src}
                  original={item.original || item.src}
                  width={item.width}
                  height={item.height}
                  title={item.label + "记录"}
                  alt={"Route Monitor 隔离样例，" + item.body}
                  priority
                />
              </div>
            )}
          </Choices>
        </article>
      </div>
    </section>
  );
}
