/**
 * 头像静态资源统一出口 —— import.meta.glob 预打包，离线可用。
 * key = 文件名，value = 打包后的资源 URL。
 */
const modules = import.meta.glob("./avatars/*.jpg", { eager: true, import: "default" }) as Record<string, string>;

export function assetFor(file: string): string {
  return modules[`./avatars/${file}`] ?? "";
}
