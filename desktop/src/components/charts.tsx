import { useEffect, useRef } from "react";
import * as echarts from "echarts";
import { themeOf, type ThemeName } from "../tokens";

function useChart(option: echarts.EChartsOption, theme: ThemeName) {
  const ref = useRef<HTMLDivElement>(null);
  const chartRef = useRef<echarts.ECharts>();

  useEffect(() => {
    if (!ref.current) return;
    const chart = echarts.init(ref.current);
    chartRef.current = chart;
    const onResize = () => chart.resize();
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      chart.dispose();
    };
  }, []);

  useEffect(() => {
    chartRef.current?.setOption(option, true);
  }, [option, theme]);

  return ref;
}

/** 攻击面趋势 / 报告生成趋势 —— 双折线 + 面积 */
export function TrendChart({
  theme,
  dates,
  found,
  total,
  foundLabel,
  totalLabel,
}: {
  theme: ThemeName;
  dates: string[];
  found: number[];
  total: number[];
  foundLabel: string;
  totalLabel: string;
}) {
  const t = themeOf(theme);
  const option: echarts.EChartsOption = {
    backgroundColor: "transparent",
    grid: { left: 34, right: 12, top: 14, bottom: 26 },
    tooltip: { trigger: "axis" },
    xAxis: {
      type: "category",
      data: dates,
      axisLine: { lineStyle: { color: t.gridLine } },
      axisTick: { show: false },
      axisLabel: { fontFamily: "JetBrains Mono", fontSize: 10, color: t.textMuted },
    },
    yAxis: {
      type: "value",
      splitLine: { lineStyle: { color: t.gridLine } },
      axisLabel: { fontFamily: "JetBrains Mono", fontSize: 10, color: t.textMuted },
    },
    series: [
      {
        name: foundLabel,
        type: "line",
        data: found,
        smooth: false,
        symbol: "none",
        lineStyle: { color: t.accentPrimary, width: 2 },
        areaStyle: {
          color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
            { offset: 0, color: t.accentPrimary + "52" },
            { offset: 1, color: t.accentPrimary + "00" },
          ]),
        },
        itemStyle: { color: t.accentPrimary },
      },
      {
        name: totalLabel,
        type: "line",
        data: total,
        smooth: false,
        symbol: "none",
        lineStyle: { color: t.accentPurple, width: 2 },
        itemStyle: { color: t.accentPurple },
      },
    ],
  };
  const ref = useChart(option, theme);
  return <div ref={ref} className="h-full w-full" />;
}

/** 三态判定 / 导出格式 —— 环图（真实 SVG 弧段语义，ECharts 实现） */
export function MixDonut({
  theme,
  data,
  centerValue,
  centerLabel,
}: {
  theme: ThemeName;
  data: { label: string; value: number; pct: string }[];
  centerValue: string;
  centerLabel: string;
}) {
  const t = themeOf(theme);
  const colors = [t.semRed, t.semGreen, t.semAmber];
  const option: echarts.EChartsOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "item" },
    title: {
      text: centerValue,
      subtext: centerLabel,
      left: "center",
      top: "34%",
      textStyle: { fontFamily: "JetBrains Mono", fontSize: 26, fontWeight: 600, color: t.textPrimary },
      subtextStyle: { fontFamily: "JetBrains Mono", fontSize: 9, color: t.textMuted },
    },
    series: [
      {
        type: "pie",
        radius: ["72%", "92%"],
        label: { show: false },
        labelLine: { show: false },
        itemStyle: { borderColor: "transparent", borderWidth: 0 },
        data: data.map((d, i) => ({ name: d.label, value: d.value, itemStyle: { color: colors[i] } })),
      },
    ],
  };
  const ref = useChart(option, theme);
  return <div ref={ref} className="h-full w-full" />;
}

/** 图例列（环图右侧） */
export function MixLegend({
  theme,
  data,
}: {
  theme: ThemeName;
  data: { label: string; value: number; pct: string }[];
}) {
  const t = themeOf(theme);
  const colors = [t.semRed, t.semGreen, t.semAmber];
  return (
    <div className="flex flex-1 flex-col gap-2.5">
      {data.map((d, i) => (
        <div key={d.label} className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-sm" style={{ background: colors[i] }} />
          <div className="flex flex-col gap-0.5">
            <span className="text-[10.5px] text-legend">{d.label}</span>
            <span className="font-mono text-[11px] text-ink">
              {d.value} · {d.pct}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}
