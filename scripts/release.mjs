#!/usr/bin/env node
/**
 * Bump de versão do engine.
 *
 *   npm run release          3.7.3 -> 3.7.4
 *   npm run release minor    3.7.3 -> 3.8.0
 *   npm run release major    3.7.3 -> 4.0.0
 *   npm run release 4.1.0    versão exata
 *
 * A versão vive em dois lugares (`package.json` e `export const VERSION` em
 * `src/index.ts`) e `tests/setup.test.ts` falha quando eles divergem. Este script só
 * edita os dois arquivos: não roda testes, não commita e não cria tag.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const SEMVER = /^(\d+)\.(\d+)\.(\d+)$/

/** A linha da versão em cada arquivo. Editamos por regex para não reformatar o resto. */
const SITES = [
  { file: 'package.json', re: /^(\s*"version"\s*:\s*")(\d+\.\d+\.\d+)(")/m },
]

/** Próxima versão a partir da atual. `arg` é patch (padrão), minor, major ou um x.y.z. */
export function nextVersion(current, arg = 'patch') {
  const parsed = SEMVER.exec(current)
  if (!parsed) throw new Error(`versão atual inválida: "${current}" (esperado x.y.z)`)
  const [major, minor, patch] = parsed.slice(1).map(Number)

  if (SEMVER.test(arg)) return arg
  if (arg === 'patch') return `${major}.${minor}.${patch + 1}`
  if (arg === 'minor') return `${major}.${minor + 1}.0`
  if (arg === 'major') return `${major + 1}.0.0`
  throw new Error(`argumento inválido: "${arg}" (use patch, minor, major ou uma versão x.y.z)`)
}

function readSite(root, { file, re }) {
  const path = join(root, file)
  const text = readFileSync(path, 'utf8')
  const found = re.exec(text)
  if (!found) throw new Error(`não encontrei a linha da versão em ${file} (esperado ${re})`)
  return { path, text, found }
}

/** Versão como está em cada arquivo hoje — sem assumir que as duas batem. */
export function readVersions(root) {
  const [pkg, src] = SITES.map((site) => readSite(root, site).found[2])
  return { pkg, src }
}

/**
 * Escreve `version` nos dois arquivos. Lê e valida os dois ANTES de escrever qualquer
 * um: um arquivo fora do formato esperado aborta tudo em vez de deixar metade bumpada.
 */
export function writeVersion(root, version) {
  if (!SEMVER.test(version)) throw new Error(`versão inválida: "${version}" (esperado x.y.z)`)

  const sites = SITES.map((site) => ({ ...site, ...readSite(root, site) }))
  for (const { path, text, re } of sites) {
    writeFileSync(path, text.replace(re, `$1${version}$3`))
  }
  return SITES.map((s) => s.file)
}

function main(argv) {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..')
  const { pkg, src } = readVersions(root)

  if (pkg !== src) {
    console.warn(
      `aviso: package.json (${pkg}) e src/index.ts (${src}) estavam fora de sincronia. ` +
      'Os dois vão para a versão nova.',
    )
  }

  const version = nextVersion(pkg, argv[0])
  const files = writeVersion(root, version)

  console.log(`${pkg} → ${version}`)
  for (const file of files) console.log(`  ${file}`)
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main(process.argv.slice(2))
  } catch (error) {
    console.error(`release: ${error.message}`)
    process.exitCode = 1
  }
}
