import React, { useState } from "react";
import {
  Route,
  GitCompareArrows,
  FileCheck2,
  Radio,
  ArrowDownToLine,
} from "lucide-react";
import { Action, Choices, Figure, HeroCopy, Mark } from "./ui.jsx";
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
    <section className="pi-hero route-hero">
      <div className="pi-container">
        <div className="route-heading">
          <HeroCopy
            mark={<Mark Icon={Route}>Mihomo / ShellCrash</Mark>}
            title={
              <>
                一条连接出错，
                <br />
                沿着出口查。
              </>
            }
            description="从连接错误开始，比较同一目标在不同出口的结果，再核对调整后的复验回执。"
          />
          <div className="pi-actions">
            <Action href="/download" icon={ArrowDownToLine}>
              下载 macOS 应用
            </Action>
            <Action href="#start" tone="ghost">
              安装说明
            </Action>
          </div>
        </div>
        <div className="route-case">
          <div className="route-case-heading">
            <h2>一次复测的完整记录</h2>
            <span>隔离样例 · api.example.com</span>
          </div>
          <Choices
            label="复测阶段"
            tabs={steps}
            value={step}
            onChange={setStep}
          >
            {(item) => (
              <div className="route-case-grid">
                <div className="route-receipt">
                  <small>{item.path}</small>
                  <strong>{item.status}</strong>
                  <p>{item.body}</p>
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
        </div>
      </div>
    </section>
  );
}
