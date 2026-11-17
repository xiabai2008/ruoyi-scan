import { describe, expect, it } from "vitest";
import { validateTarget } from "../src/services/target";

// 扫描目标校验（src/services/target.ts）
//
// 这层是「用户输入 → 建任务」的唯一闸门。旧实现只校验非空，输入 abc 会直接
// 建任务并以登录爆破模式跑完，产出两条 UNKNOWN 和一份报告（测评 P1-6）。
// 所以这里的用例按「真实会踩到的输入」写，不按函数分支写。

describe("validateTarget — 空与脏输入", () => {
  it("空串与纯空白都拒绝且文案相同", () => {
    expect(validateTarget("")).toEqual({ ok: false, error: "目标 URL 不能为空" });
    expect(validateTarget("   ")).toEqual({ ok: false, error: "目标 URL 不能为空" });
  });

  it("中间含空格拒绝（防粘贴两段地址）", () => {
    const r = validateTarget("http://a b.com");
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.error).toContain("空格");
  });

  it("控制字符拒绝（防粘贴不可见字符）", () => {
    const r = validateTarget("http://a.com/\u0007");
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.error).toContain("控制字符");
  });

  it("首尾空白与换行被 trim，不算非法", () => {
    // 从终端/文档复制地址时常带尾换行，这里要求宽容而不是报错
    expect(validateTarget("  http://a.com/\n")).toEqual({ ok: true, url: "http://a.com/" });
  });
});

describe("validateTarget — 裸主机名（历史事故回归）", () => {
  it("abc 被拒", () => {
    const r = validateTarget("abc");
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.error).toContain("不是有效地址");
  });

  it("deadbeef 不被误判为 IPv6 而放过", () => {
    // IPv6 字面量必然含冒号；旧正则只认 [0-9a-f:] 会把 deadbeef 当 IPv6
    expect(validateTarget("deadbeef").ok).toBe(false);
  });

  it("localhost 例外放行", () => {
    expect(validateTarget("localhost")).toEqual({
      ok: true,
      url: "http://localhost/",
      note: "已自动补全 http://",
    });
  });

  it("单标签主机带端口放行（内网常见写法）", () => {
    expect(validateTarget("ruoyi-lab:8080")).toEqual({
      ok: true,
      url: "http://ruoyi-lab:8080/",
      note: "已自动补全 http://",
    });
  });
});

describe("validateTarget — 协议与端口", () => {
  it("仅接受 http/https，ftp 明确报出当前协议", () => {
    const r = validateTarget("ftp://example.com");
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.error).toContain("ftp://");
  });

  it("javascript: 伪协议被解析失败挡住", () => {
    expect(validateTarget("javascript:alert(1)").ok).toBe(false);
  });

  it("缺主机名的 http:// 拒绝", () => {
    expect(validateTarget("http://").ok).toBe(false);
  });

  it("端口超范围拒绝", () => {
    expect(validateTarget("example.com:99999").ok).toBe(false);
  });

  it("无协议时自动补 http:// 并回传提示", () => {
    const r = validateTarget("demo.example.com");
    expect(r).toEqual({ ok: true, url: "http://demo.example.com/", note: "已自动补全 http://" });
  });

  it("已带协议时不回传提示", () => {
    const r = validateTarget("https://demo.example.com/");
    expect(r).toEqual({ ok: true, url: "https://demo.example.com/" });
  });
});

describe("validateTarget — 归一化", () => {
  it("协议与主机名转小写", () => {
    expect(validateTarget("HTTP://EXAMPLE.COM")).toEqual({ ok: true, url: "http://example.com/" });
  });

  it("IP + 端口 + 上下文路径原样保留", () => {
    // 若依部署在 /ruoyi 子路径下很常见，路径不能被吞
    expect(validateTarget("192.168.1.1:8080/ruoyi")).toEqual({
      ok: true,
      url: "http://192.168.1.1:8080/ruoyi",
      note: "已自动补全 http://",
    });
  });

  it("IPv4 与 IPv6 字面量都放行", () => {
    expect(validateTarget("127.0.0.1:8080").ok).toBe(true);
    const v6 = validateTarget("[::1]:8080");
    expect(v6.ok).toBe(true);
    expect(v6.ok === true && v6.url).toBe("http://[::1]:8080/");
  });

  it("国际化域名转 punycode", () => {
    expect(validateTarget("https://例子.com/")).toEqual({
      ok: true,
      url: "https://xn--fsqu00a.com/",
    });
  });
});

// 已知瑕疵（当前不修，先记录，避免后人以为是测试漏了）：
//   1. 协议相对地址 "//example.com" 会被静默补成 http://example.com/，
//      用户看不出自己写的是协议相对形式。建议后续显式判非法或给出 note。
//   2. 端口超范围（example.com:99999）报「目标格式无法解析」，
//      真实原因是端口越界，文案可以更准。
