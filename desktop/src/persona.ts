/**
 * 操作员人格系统 —— 头像 / 代号 / 称呼 / 播报 / 音效 的单一数据源。
 *
 * 设计要点：
 *  - 头像 = /src/assets/avatars/ 下的静态资源（打包进应用，离线可用），
 *    id 即文件名；自定义头像走 WebAsset 协议（persona:// 自定义文件），
 *    原始路径持久化在 localStorage，由 tauri://localhost 的 <base> 转成 asset://。
 *  - 称呼 greet 拼接在侧边栏问候语后面（"引擎在线，随时开工" + "，xx"！）。
 *  - speak 控制扫描完成时的枚依播报条 + 可选系统通知；sound 控制完成音效。
 *  - 修改任何人格字段后调用 personaAppearance() 重绘窗口图标。
 */
import type { ThemeName } from "./tokens";

export type OperatorId =
  | "v01_smile"
  | "v02_pensive"
  | "v04_gaze"
  | "c01_citypop"
  | "c02_sunset"
  | "c03_neon"
  | "c04_cel"
  | "v2_01_chin"
  | "v2_02_tousle"
  | "v2_03_lollipop"
  | "c2_02_wind"
  | "custom";

export interface OperatorMeta {
  id: OperatorId;
  file: string;
  name: string;
  theme: ThemeName;
  greet: string;
}

export const OPERATORS: OperatorMeta[] = [
  { id: "v01_smile", file: "avatar_v01_lookback_smile.jpg", name: "枚依·回眸", theme: "bluewhite", greet: "回眸一笑，扫描开跑" },
  { id: "v02_pensive", file: "avatar_v02_pensive_lookdown.jpg", name: "枚依·沉思", theme: "mintfresh", greet: "沉思路线上，先扫再说" },
  { id: "v04_gaze", file: "avatar_v04_frontal_gaze.jpg", name: "枚依·注视", theme: "darkneon", greet: "正面注视，目标锁定" },
  { id: "c01_citypop", file: "avatar_c01_citypop_pastel.jpg", name: "枚依·CityPop", theme: "creampop", greet: "CityPop 味儿的今天也要扫漏洞" },
  { id: "c02_sunset", file: "avatar_c02_sunset_warm.jpg", name: "枚依·落日", theme: "creampop", greet: "落日余晖里也照扫不误" },
  { id: "c03_neon", file: "avatar_c03_cyberpunk_neon.jpg", name: "枚依·霓虹", theme: "darkneon", greet: "霓虹夜巡，漏洞无处藏" },
  { id: "c04_cel", file: "avatar_c04_classic_cel_shaded.jpg", name: "枚依·赛璐璐", theme: "bluewhite", greet: "经典赛璐璐，永远的神" },
  { id: "v2_01_chin", file: "avatar_v2_01_side_profile_rest_chin.jpg", name: "枚依·托腮", theme: "mintfresh", greet: "托腮看着进度条跑完" },
  { id: "v2_02_tousle", file: "avatar_v2_02_tilt_back_tousle_hair.jpg", name: "枚依·乱发", theme: "darkneon", greet: "头发乱了也要扫完这轮" },
  { id: "v2_03_lollipop", file: "avatar_v2_03_lollipop_wink.jpg", name: "枚依·棒棒糖", theme: "creampop", greet: "wink！这一轮稳了" },
  { id: "c2_02_wind", file: "avatar_c2_02_wind_hair_sunset.jpg", name: "枚依·风吹", theme: "mintfresh", greet: "风起时，扫描正好开始" },
];

const CUSTOM_AVATAR_KEY = "rs.customAvatarPath";

export function customAvatarPath(): string | null {
  try {
    return localStorage.getItem(CUSTOM_AVATAR_KEY);
  } catch {
    return null;
  }
}

export function setCustomAvatarPath(p: string | null) {
  try {
    if (p) localStorage.setItem(CUSTOM_AVATAR_KEY, p);
    else localStorage.removeItem(CUSTOM_AVATAR_KEY);
  } catch {
    /* ignore */
  }
}

export interface OperatorConfig {
  id: OperatorId;
  callsign: string;
  greet: string;
  avatar: string; // img src（静态资源 URL 或 asset://）
  speak: boolean;
  sound: boolean;
}

const DEF_CALLSIGN = "枚依";

export function defaultOperator(): OperatorConfig {
  const m = OPERATORS[0];
  return { id: m.id, callsign: DEF_CALLSIGN, greet: m.greet, avatar: "", speak: true, sound: true };
}

export function operatorById(id: OperatorId): OperatorConfig | null {
  const m = OPERATORS.find((o) => o.id === id);
  if (!m) return null;
  return {
    id: m.id,
    callsign: m.name.startsWith(DEF_CALLSIGN) ? DEF_CALLSIGN : m.name,
    greet: m.greet,
    avatar: "",
    speak: false,
    sound: false,
  };
}

/** persona:// 协议 → 浏览器可直接 <img> 的 URL（自定义头像用） */
export function personaUrl(p: string): string {
  return "persona://" + p.replace(/\\/g, "/");
}

/** 生成自定义头像的默认称呼 */
export function customCallsign(): string {
  return DEF_CALLSIGN;
}

export function operatorGreetLine(id: OperatorId): string {
  return OPERATORS.find((o) => o.id === id)?.greet || "";
}
