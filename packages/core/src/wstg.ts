/** OWASP Web Security Testing Guide v4.2 categories. */
export const WSTG = [
  { id: "INFO", title: "Recolección de información", titleEn: "Information gathering" },
  { id: "CONF", title: "Configuración y despliegue", titleEn: "Configuration and deployment" },
  { id: "IDNT", title: "Gestión de identidades", titleEn: "Identity management" },
  { id: "ATHN", title: "Autenticación", titleEn: "Authentication" },
  { id: "ATHZ", title: "Autorización", titleEn: "Authorization" },
  { id: "SESS", title: "Gestión de sesiones", titleEn: "Session management" },
  { id: "INPV", title: "Validación de entradas", titleEn: "Input validation" },
  { id: "ERRH", title: "Manejo de errores", titleEn: "Error handling" },
  { id: "CRYP", title: "Criptografía", titleEn: "Cryptography" },
  { id: "BUSL", title: "Lógica de negocio", titleEn: "Business logic" },
  { id: "CLNT", title: "Lado del cliente", titleEn: "Client side" },
  { id: "APIT", title: "APIs", titleEn: "APIs" },
] as const;

/** A category title in the given language. */
export function wstgTitle(c: { title: string; titleEn: string }, lang: "es" | "en"): string {
  return lang === "en" ? c.titleEn : c.title;
}
