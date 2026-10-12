/**
 * 头像静态资源统一出口 —— import.meta.glob 预打包，离线可用。
 * key = 文件名，value = 打包后的资源 URL。
 */
// 查找前缀必须与下方 glob 字面量一致（glob 只能是字面量，前缀抽成常量供查找复用）
const AVATAR_DIR = "./avatars/";
const modules = import.meta.glob<string>("./avatars/*.{jpg,jpeg,JPG,JPEG}", { eager: true, import: "default" });

export function assetFor(file: string): string {
  // 非法 key（非字符串 / 空串 / 路径分隔符 / 目录穿越）一律视为未命中，避免拼出诡异路径
  if (typeof file !== "string" || !file || file.includes("/") || file.includes("\\") || file.includes("..")) {
    return "";
  }
  const url = modules[`${AVATAR_DIR}${file}`];
  if (url) return url;
  if (import.meta.env.DEV) console.warn(`[avatars] 未找到头像资源: ${file}`);
  return "";
}
