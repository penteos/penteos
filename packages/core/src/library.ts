import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Severity } from "@penteos/schema";
import { z } from "zod";

/**
 * The findings library: reusable write-ups so nobody rewrites "version
 * disclosure" on every engagement. Templates are plain JSON files, one per finding, so a team can
 * keep them in a git repository and review changes like code.
 */

export const FindingTemplate = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]{1,60}$/),
  title: z.string().min(1),
  severity: Severity,
  cwe: z.array(z.string().regex(/^CWE-\d+$/)).default([]),
  description: z.string().default(""),
  impact: z.string().default(""),
  remediation: z.string().default(""),
  references: z.array(z.string()).default([]),
  tags: z.array(z.string()).default([]),
});
export type FindingTemplate = z.infer<typeof FindingTemplate>;

const BUILTIN: Array<z.input<typeof FindingTemplate>> = [
  {
    id: "version-disclosure",
    title: "Divulgación de versión del software",
    severity: "info",
    cwe: ["CWE-200"],
    description: "El servicio revela el producto y la versión exacta que ejecuta (cabeceras HTTP, banners o páginas de error).",
    impact: "Facilita a un atacante identificar vulnerabilidades conocidas aplicables a esa versión y dirigir ataques específicos sin necesidad de sondear.",
    remediation: "Ocultar o generalizar los banners y cabeceras que exponen versiones (por ejemplo `Server`, `X-Powered-By`) y mantener el software actualizado.",
    references: ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
    tags: ["web", "information-disclosure"],
  },
  {
    id: "exposed-api-documentation",
    title: "Documentación de la API expuesta sin autenticación",
    severity: "low",
    cwe: ["CWE-200", "CWE-1059"],
    description: "La API publica sin autenticación su contrato completo (OpenAPI/Swagger, introspección de GraphQL o un diccionario de datos): todas las rutas, parámetros, modelos y campos.",
    impact: "Entrega a un atacante el mapa completo de la superficie y del modelo de datos, incluidos endpoints internos o de administración y los campos con datos personales, sin necesidad de descubrirlos. Acelera la búsqueda de controles de acceso rotos y de asignación masiva de atributos.",
    remediation: "Publicar la documentación solo en entornos internos o detrás de autenticación, deshabilitar la introspección de GraphQL en producción y revisar que el contrato no exponga rutas ni campos que no deban ser públicos.",
    references: ["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/"],
    tags: ["web", "api", "information-disclosure"],
  },
  {
    id: "missing-security-headers",
    title: "Cabeceras de seguridad HTTP ausentes",
    severity: "low",
    cwe: ["CWE-693"],
    description: "Las respuestas no incluyen una o más cabeceras de seguridad recomendadas (Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options o Referrer-Policy).",
    impact: "Reduce las defensas del navegador frente a ataques como XSS, clickjacking, sniffing de tipos MIME o degradación a HTTP.",
    remediation: "Configurar las cabeceras faltantes en el servidor o en la capa de CDN, comenzando por HSTS y una CSP restrictiva.",
    references: ["https://owasp.org/www-project-secure-headers/"],
    tags: ["web", "hardening"],
  },
  {
    id: "permissive-cors",
    title: "Política CORS permisiva",
    severity: "medium",
    cwe: ["CWE-942"],
    description: "La aplicación refleja orígenes arbitrarios en `Access-Control-Allow-Origin` y permite credenciales.",
    impact: "Un sitio malicioso puede leer respuestas autenticadas de la aplicación en nombre de un usuario que lo visite.",
    remediation: "Restringir los orígenes permitidos a una lista explícita y no combinar orígenes dinámicos con `Access-Control-Allow-Credentials: true`.",
    references: ["https://portswigger.net/web-security/cors"],
    tags: ["web", "cors"],
  },
  {
    id: "idor",
    title: "Referencia directa insegura a objetos (IDOR)",
    severity: "high",
    cwe: ["CWE-639"],
    description: "La aplicación permite acceder o modificar recursos de otros usuarios cambiando un identificador en la petición, sin verificar que el usuario autenticado tenga permiso sobre ese recurso.",
    impact: "Un usuario autenticado puede leer o alterar información de otros usuarios.",
    remediation: "Verificar en el servidor la autorización sobre cada recurso solicitado, en función del usuario autenticado y no de identificadores enviados por el cliente.",
    references: ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
    tags: ["web", "access-control"],
  },
  {
    id: "reflected-xss",
    title: "Cross-Site Scripting (XSS) reflejado",
    severity: "medium",
    cwe: ["CWE-79"],
    description: "Un parámetro de la petición se refleja en la respuesta sin codificación adecuada, permitiendo ejecutar JavaScript en el navegador de la víctima.",
    impact: "Robo de sesión, acciones en nombre del usuario o suplantación de contenido mediante un enlace manipulado.",
    remediation: "Codificar la salida según el contexto (HTML, atributo, JavaScript, URL) y aplicar una Content-Security-Policy restrictiva.",
    references: ["https://owasp.org/www-community/attacks/xss/"],
    tags: ["web", "injection"],
  },
  {
    id: "sql-injection",
    title: "Inyección SQL",
    severity: "critical",
    cwe: ["CWE-89"],
    description: "Datos controlados por el usuario se incorporan a consultas SQL sin parametrizar.",
    impact: "Lectura o modificación arbitraria de la base de datos y, según el motor, ejecución de comandos en el servidor.",
    remediation: "Usar consultas parametrizadas o un ORM en todos los accesos a la base de datos y aplicar el principio de mínimo privilegio a la cuenta de la aplicación.",
    references: ["https://owasp.org/www-community/attacks/SQL_Injection"],
    tags: ["web", "injection"],
  },
  {
    id: "default-credentials",
    title: "Credenciales por defecto o débiles",
    severity: "high",
    cwe: ["CWE-1392"],
    description: "Una interfaz de administración o servicio acepta credenciales por defecto o trivialmente adivinables.",
    impact: "Acceso no autorizado con los privilegios de esa cuenta.",
    remediation: "Cambiar las credenciales por defecto, exigir contraseñas robustas y, cuando sea posible, autenticación multifactor.",
    references: [],
    tags: ["authentication"],
  },
  {
    id: "directory-listing",
    title: "Listado de directorios habilitado",
    severity: "low",
    cwe: ["CWE-548"],
    description: "El servidor web muestra el contenido de directorios sin un archivo índice.",
    impact: "Expone archivos que no deberían ser públicos (respaldos, configuraciones, código) y facilita el reconocimiento.",
    remediation: "Deshabilitar el listado de directorios en la configuración del servidor y revisar los archivos expuestos.",
    references: [],
    tags: ["web", "information-disclosure"],
  },
  {
    id: "insecure-cookies",
    title: "Cookies de sesión sin atributos de seguridad",
    severity: "low",
    cwe: ["CWE-614", "CWE-1004"],
    description: "Las cookies de sesión no tienen uno o más de los atributos `Secure`, `HttpOnly` o `SameSite`.",
    impact: "Aumenta el riesgo de robo de sesión mediante XSS, tráfico sin cifrar o ataques CSRF.",
    remediation: "Emitir las cookies de sesión con `Secure`, `HttpOnly` y `SameSite=Lax` o `Strict`.",
    references: [],
    tags: ["web", "session"],
  },
  {
    id: "weak-tls",
    title: "Configuración TLS débil",
    severity: "medium",
    cwe: ["CWE-326"],
    description: "El servicio acepta versiones de protocolo o suites de cifrado obsoletas.",
    impact: "Un atacante en posición de red podría degradar o descifrar comunicaciones.",
    remediation: "Permitir solo TLS 1.2 y 1.3 con suites modernas y deshabilitar los protocolos y cifrados obsoletos.",
    references: ["https://ssl-config.mozilla.org/"],
    tags: ["tls"],
  },
  {
    id: "exposed-admin-interface",
    title: "Interfaz de administración expuesta",
    severity: "medium",
    cwe: ["CWE-284"],
    description: "Una interfaz de administración es accesible desde redes que no deberían alcanzarla.",
    impact: "Amplía la superficie de ataque sobre las funciones más privilegiadas del sistema (fuerza bruta, explotación de vulnerabilidades del panel).",
    remediation: "Restringir el acceso por red (VPN, lista de IPs) o colocarla detrás de un mecanismo de autenticación robusto (SSO con MFA).",
    references: [],
    tags: ["web", "access-control"],
  },
  {
    id: "no-login-rate-limit",
    title: "Ausencia de limitación de intentos en el inicio de sesión",
    severity: "medium",
    cwe: ["CWE-307"],
    description: "El formulario de inicio de sesión no limita ni ralentiza los intentos fallidos.",
    impact: "Permite ataques de fuerza bruta o de relleno de credenciales contra las cuentas de usuarios.",
    remediation: "Aplicar limitación por cuenta y por origen, bloqueos temporales progresivos y monitoreo de intentos fallidos.",
    references: [],
    tags: ["web", "authentication"],
  },
  {
    id: "subdomain-takeover",
    title: "Subdominio vulnerable a toma de control",
    severity: "high",
    cwe: ["CWE-284"],
    description: "Un registro DNS apunta a un servicio externo que ya no está reclamado por la organización.",
    impact: "Un atacante puede reclamar el recurso y servir contenido bajo un subdominio legítimo (phishing, robo de cookies del dominio).",
    remediation: "Eliminar los registros DNS que apuntan a recursos dados de baja y auditar periódicamente los registros CNAME.",
    references: ["https://github.com/EdOverflow/can-i-take-over-xyz"],
    tags: ["dns"],
  },
];

export type TemplateSource = "builtin" | "custom" | "plugin";

export class FindingLibrary {
  private readonly builtin = new Map(BUILTIN.map((t) => [t.id, FindingTemplate.parse(t)]));
  private pluginTemplates: () => Array<FindingTemplate & { plugin: string }> = () => [];

  /** Templates of running plugins: above the built-in ones, below the organization's own. */
  usePluginTemplates(source: () => Array<FindingTemplate & { plugin: string }>): void {
    this.pluginTemplates = source;
  }

  private fromPlugins(): Map<string, FindingTemplate & { plugin: string }> {
    try {
      return new Map(this.pluginTemplates().map((t) => [t.id, t]));
    } catch {
      return new Map();
    }
  }

  constructor(private readonly dir?: string) {
    if (dir) mkdirSync(dir, { recursive: true });
  }

  private custom(): Map<string, FindingTemplate> {
    const out = new Map<string, FindingTemplate>();
    if (!this.dir) return out;
    for (const file of readdirSync(this.dir).filter((f) => f.endsWith(".json"))) {
      try {
        const t = FindingTemplate.parse(JSON.parse(readFileSync(join(this.dir, file), "utf8")));
        out.set(t.id, t);
      } catch {
        /* an invalid file never breaks the library */
      }
    }
    return out;
  }

  /** The organization's own templates override the built-in ones with the same id. */
  list(query?: string): Array<FindingTemplate & { source: TemplateSource; plugin?: string }> {
    const custom = this.custom();
    const plugins = this.fromPlugins();
    const all: Array<FindingTemplate & { source: TemplateSource; plugin?: string }> = [
      ...[...this.builtin.values()].filter((t) => !custom.has(t.id) && !plugins.has(t.id)).map((t) => ({ ...t, source: "builtin" as const })),
      ...[...plugins.values()].filter((t) => !custom.has(t.id)).map((t) => ({ ...t, source: "plugin" as const })),
      ...[...custom.values()].map((t) => ({ ...t, source: "custom" as const })),
    ];
    const q = query?.trim().toLowerCase();
    const filtered = q
      ? all.filter((t) => [t.id, t.title, t.description, ...t.tags, ...t.cwe].some((v) => v.toLowerCase().includes(q)))
      : all;
    return filtered.sort((a, b) => a.title.localeCompare(b.title));
  }

  get(id: string): FindingTemplate | undefined {
    return this.custom().get(id) ?? this.fromPlugins().get(id) ?? this.builtin.get(id);
  }

  save(input: unknown): FindingTemplate {
    if (!this.dir) throw new Error("this library cannot store templates");
    const template = FindingTemplate.parse(input);
    writeFileSync(join(this.dir, `${template.id}.json`), `${JSON.stringify(template, null, 2)}\n`);
    return template;
  }
}

/** A readable, stable id for a template from its title ("Divulgación de versión" → "divulgacion-de-version"). */
export function templateId(title: string): string {
  return title
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60) || "plantilla";
}
