// Diot IoT 漏洞分析插件（AGH 后端插件）
// ============================================
// 垂直服务 IoT 挖洞：把 LIVA 复现的经验固化为 AGH 可调用的工具集。
// 每个工具子进程调用 LIVA/Diot 的 Python 分析核心，返回结构化结果。
// 模型在会话中选中工具 → 工具执行 → 结果记录进 Harness（Web/CLI 可见）。

import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const Kind = Symbol.for('TypeBox.Kind')

// ---------- 基础配置 ----------
// Diot/LIVA Python 环境与核心路径（可用环境变量覆盖）
const DIOT_PYTHON = process.env.DIOT_PYTHON ?? 'D:/AgentLearning/IOT Agent/LIVA/.venv/Scripts/python.exe'
const DIOT_ROOT = process.env.DIOT_ROOT ?? 'D:/AgentLearning/IOT Agent/Diot'
const LIVA_ROOT = process.env.LIVA_ROOT ?? 'D:/AgentLearning/IOT Agent/LIVA'

// 常用参数 Schema（TypeBox 手写，避免外部依赖）
const strParam = (desc, max = 4096) => ({ [Kind]: 'String', type: 'string', description: desc, maxLength: max })
const numParam = (desc) => ({ [Kind]: 'Number', type: 'number', description: desc })

// 只读、非破坏、并发安全、封闭世界、replay safe、无需审批（本插件只做分析）
const META = {
  isReadOnly: true,
  isDestructive: false,
  isConcurrencySafe: true,
  isOpenWorld: false,
  replay: 'safe',
  costHint: undefined,
  deferLoading: false,
  requiresApproval: 'never',
}

// ---------- 子进程调用 Python 核心 ----------
function runPython(args, cwd, timeoutMs = 300000) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(DIOT_PYTHON, args, {
      cwd,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let out = ''
    let err = ''
    const timer = setTimeout(() => {
      child.kill()
      reject(new Error(`python timeout after ${timeoutMs}ms`))
    }, timeoutMs)
    child.stdout.on('data', (d) => { out += d.toString() })
    child.stderr.on('data', (d) => { err += d.toString() })
    child.on('close', (code) => {
      clearTimeout(timer)
      if (code === 0) resolvePromise(out)
      else reject(new Error(`python exit ${code}: ${err.slice(0, 800)}`))
    })
  })
}

// 读取分析结果文件（结构化返回给模型）
function readJsonSafe(path) {
  try {
    if (existsSync(path)) return JSON.parse(readFileSync(path, 'utf8'))
  } catch { /* ignore */ }
  return null
}

// 读文本文件前 N 行
function readTextHead(path, maxLines = 60) {
  try {
    if (!existsSync(path)) return ''
    const lines = readFileSync(path, 'utf8').split(/\r?\n/)
    return lines.slice(0, maxLines).join('\n')
  } catch { return '' }
}

// 通用：确保结果目录存在
function ensureResultDir(device, binaryName) {
  const dir = resolve(DIOT_ROOT, 'result', device, binaryName)
  mkdirSync(dir, { recursive: true })
  return dir
}

// ---------- 工具 1：ELF 信息（真执行） ----------
const elfInfo = {
  name: 'diot_elf_info',
  description: '分析一个 IoT 固件 ELF 二进制的架构/类型/依赖库。输入 binary 路径与 rootfs 搜索目录，真实解析 ELF 头 + 动态依赖，输出架构/字节序/依赖库列表。',
  parameters: {
    [Kind]: 'Object',
    type: 'object',
    properties: {
      binary: strParam('ELF 二进制文件绝对路径，如 D:/AgentLearning/IOT Agent/firmware/rootfs/cgibin', 1024),
      rootfs: strParam('rootfs 目录（搜索依赖库用）', 1024),
      device: strParam('设备/项目名，如 DIR816L-cgibin', 128),
    },
    required: ['binary', 'rootfs', 'device'],
    additionalProperties: false,
  },
  meta: META,
  async execute({ binary, rootfs, device }) {
    const binName = binary.split(/[\\/]/).pop().replace(/[^\w.-]/g, '_')
    const outDir = ensureResultDir(device, binName)
    // 真跑 elf 阶段（非 dry-run）：解析 ELF + 找依赖库 + common_functions
    const stdout = await runPython(
      ['diot.py', binary, rootfs, device, '--stages', 'elf'],
      DIOT_ROOT,
      120000,
    ).catch((e) => `elf stage error: ${e.message}`)
    // 用 pyelftools 提取结构化信息（不依赖 config/db）
    const script = `
import sys, io, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
info = {'binary': r'''${binary.replace(/\\/g, '/')}''', 'arch': None, 'endian': None, 'needed': []}
try:
    with open(r'''${binary.replace(/\\/g, '/')}''', 'rb') as f:
        elf = ELFFile(f)
        h = elf.header
        info['arch'] = h['e_machine']
        info['endian'] = '<' if h['e_ident']['EI_DATA'] == 'ELFDATA2LSB' else '>'
        info['elf_class'] = h['e_ident']['EI_CLASS']
        for sec in elf.iter_sections():
            if isinstance(sec, DynamicSection):
                for t in sec.iter_tags():
                    if t.entry.d_tag == 'DT_NEEDED':
                        info['needed'].append(t.needed)
except Exception as e:
    info['error'] = str(e)
print(json.dumps(info, ensure_ascii=False))
`
    let parsed
    try {
      const out = await runPython(['-c', script], DIOT_ROOT, 60000)
      parsed = JSON.parse(out.trim().split('\n').pop())
    } catch { parsed = { parseError: true } }
    return {
      content: [{ type: 'text', text: JSON.stringify({ elf: parsed, pipeline: stdout.slice(0, 500) }, null, 2) }],
      structured: { elf: parsed, resultDir: outDir },
    }
  },
}

// ---------- 工具 2：IDA 调用图（真执行） ----------
const callgraph = {
  name: 'diot_callgraph',
  description: '提取 ELF 的完整调用图（真调 IDA 桥 http://127.0.0.1:8082/callgraph，MIPS jalr $t9 间接调用可靠解析）。输出函数数量 + 调用关系 JSON，并保存到 result 目录供后续 taint 使用。',
  parameters: {
    [Kind]: 'Object',
    type: 'object',
    properties: {
      binary: strParam('ELF 二进制绝对路径', 1024),
      device: strParam('设备/项目名', 128),
    },
    required: ['binary', 'device'],
    additionalProperties: false,
  },
  meta: { ...META, isReadOnly: false, isConcurrencySafe: false, requiresApproval: 'always' },
  async execute({ binary, device }) {
    const binName = binary.split(/[\\/]/).pop().replace(/[^\w.-]/g, '_')
    const outDir = ensureResultDir(device, binName)
    // 真调 IDA 桥 /callgraph（multipart：binfile + token）
    const script = `
import sys, io, json, os, urllib.request, uuid, mimetypes
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
binfile = r'''${binary.replace(/\\/g, '/')}'''
host = os.environ.get('IDA_BRIDGE_HOST', '127.0.0.1')
port = int(os.environ.get('IDA_BRIDGE_PORT', '8082'))
token = os.environ.get('IDA_BRIDGE_TOKEN', 'REPLACE_IDA_TOKEN')
boundary = '----diot' + uuid.uuid4().hex
with open(binfile, 'rb') as f:
    data = f.read()
body = bytearray()
body += (b'--' + boundary.encode() + b'\r\n')
body += (b'Content-Disposition: form-data; name="token"\r\n\r\n' + token.encode() + b'\r\n')
body += (b'--' + boundary.encode() + b'\r\n')
body += (b'Content-Disposition: form-data; name="binfile"; filename="' + os.path.basename(binfile).encode() + b'"\r\n')
body += (b'Content-Type: application/octet-stream\r\n\r\n' + data + b'\r\n')
body += (b'--' + boundary.encode() + b'--\r\n')
req = urllib.request.Request(
    'http://%s:%d/callgraph' % (host, port),
    data=bytes(body),
    headers={'Content-Type': 'multipart/form-data; boundary=' + boundary},
)
try:
    with urllib.request.urlopen(req, timeout=600) as r:
        cg = json.loads(r.read())
    out_path = r'''${outDir.replace(/\\/g, '/')}''' + '/callgraph.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(cg, f, ensure_ascii=False)
    nfuncs = len(cg.get('callgraph', cg))
    print(json.dumps({'funcs': nfuncs, 'saved': out_path, 'sample': list(cg.get('callgraph', cg).keys())[:15]}, ensure_ascii=False))
except Exception as e:
    print(json.dumps({'error': '%s: %s' % (type(e).__name__, e)}, ensure_ascii=False))
`
    const out = await runPython(['-c', script], DIOT_ROOT, 660000)
    let parsed
    try { parsed = JSON.parse(out.trim().split('\n').pop()) } catch { parsed = { raw: out.slice(0, 500) } }
    return { content: [{ type: 'text', text: JSON.stringify(parsed, null, 2) }], structured: parsed }
  },
}

// ---------- 工具 3：动态 source 发现 ----------
const sourceDiscovery = {
  name: 'diot_source_discovery',
  description: '从调用图动态发现 source 入口（*cgi_main / *main）。LIVA 教训：硬编码函数名换固件即失效，必须动态发现。输出入口函数列表。',
  parameters: {
    [Kind]: 'Object',
    type: 'object',
    properties: {
      callgraph: strParam('调用图 JSON 路径（diot_callgraph 或已有产物）', 1024),
    },
    required: ['callgraph'],
    additionalProperties: false,
  },
  meta: META,
  async execute({ callgraph }) {
    const script = `
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, r'${DIOT_ROOT.replace(/\\/g, '/')}')
from skills.source_sink import dynamic_source_discovery, sink_auto_scan
import json
cg = json.load(open(r'${callgraph.replace(/\\/g, '/')}', encoding='utf-8'))
names = []
for key in ('nodes', 'functions'):
    for it in (cg.get(key) or []):
        if isinstance(it, dict) and it.get('name'): names.append(it['name'])
sources = dynamic_source_discovery(names)
sinks = sink_auto_scan(cg)
print(json.dumps({'sources': sources, 'sink_hits': sinks, 'total_funcs': len(names)}, ensure_ascii=False))
`
    const out = await runPython(['-c', script], DIOT_ROOT)
    let parsed
    try { parsed = JSON.parse(out.trim().split('\n').pop()) } catch { parsed = { raw: out.slice(0, 500) } }
    return { content: [{ type: 'text', text: JSON.stringify(parsed, null, 2) }], structured: parsed }
  },
}

// ---------- 工具 4：wrapper sink 补入 ----------
const sinkScan = {
  name: 'diot_sink_scan',
  description: '扫描调用图中的危险函数 + 补入包装 sink（如 lxmldbc_system，内部 vsnprintf+system，CVE-2025-7836 引信）。输出最终 sink 列表。',
  parameters: {
    [Kind]: 'Object',
    type: 'object',
    properties: {
      callgraph: strParam('调用图 JSON 路径', 1024),
    },
    required: ['callgraph'],
    additionalProperties: false,
  },
  meta: META,
  async execute({ callgraph }) {
    const script = `
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, r'${DIOT_ROOT.replace(/\\/g, '/')}')
from skills.source_sink import sink_auto_scan, merge_sink_set
import json
cg = json.load(open(r'${callgraph.replace(/\\/g, '/')}', encoding='utf-8'))
hits = sink_auto_scan(cg)
merged = merge_sink_set(hits, ['system','popen','strcpy','sprintf','strcat','memcpy'])
print(json.dumps({'callgraph_sinks': hits, 'merged_with_wrappers': merged}, ensure_ascii=False))
`
    const out = await runPython(['-c', script], DIOT_ROOT)
    let parsed
    try { parsed = JSON.parse(out.trim().split('\n').pop()) } catch { parsed = { raw: out.slice(0, 500) } }
    return { content: [{ type: 'text', text: JSON.stringify(parsed, null, 2) }], structured: parsed }
  },
}

// ---------- 工具 5：验证闭环 ----------
const verify = {
  name: 'diot_verify',
  description: '对一条 source→sink 候选做验证闭环：输入可控性 / 长度约束 / 可达性 / PoC 骨架。数据流存在 ≠ 漏洞，必须验证。',
  parameters: {
    [Kind]: 'Object',
    type: 'object',
    properties: {
      src_func: strParam('source 函数名（入口，如 ssdpcgi_main）', 256),
      sink_func: strParam('sink 函数名（如 system / lxmldbc_system / strcpy）', 256),
      decompiled: strParam('该 source 函数的反编译代码（可截断）', 8192),
    },
    required: ['src_func', 'sink_func', 'decompiled'],
    additionalProperties: false,
  },
  meta: META,
  async execute({ src_func, sink_func, decompiled }) {
    const script = `
import sys, io, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, r'${DIOT_ROOT.replace(/\\/g, '/')}')
from skills.cross_elf import verification_loop, poc_template
import base64
dec = base64.b64decode(r'''${Buffer.from(decompiled).toString('base64')}''').decode('utf-8', errors='ignore')
v = verification_loop(r'''${src_func}''', r'''${sink_func}''', dec)
v['poc_template'] = poc_template(r'''${sink_func}''')
print(json.dumps(v, ensure_ascii=False))
`
    const out = await runPython(['-c', script], DIOT_ROOT)
    let parsed
    try { parsed = JSON.parse(out.trim().split('\n').pop()) } catch { parsed = { raw: out.slice(0, 500) } }
    return { content: [{ type: 'text', text: JSON.stringify(parsed, null, 2) }], structured: parsed }
  },
}

// ---------- 工具 6：跨 ELF 攻击面 ----------
const crossElf = {
  name: 'diot_cross_elf',
  description: '构建跨 ELF 攻击面模型（httpd 分发层 → cgibin 处理层）。LIVA 架构空白：单 ELF 分析器看不到跨文件数据流。输出攻击面与建议分析对象。',
  parameters: {
    [Kind]: 'Object',
    type: 'object',
    properties: {
      main_elf: strParam('主程序 ELF（分发层，如 httpd）', 1024),
      cgi_elfs: strParam('CGI 处理 ELF 列表（逗号分隔，如 cgibin）', 1024),
      cgi_entries: strParam('CGI 侧入口函数（逗号分隔，如 ssdpcgi_main,authenticationcgi_main）', 1024),
    },
    required: ['main_elf', 'cgi_elfs', 'cgi_entries'],
    additionalProperties: false,
  },
  meta: META,
  async execute({ main_elf, cgi_elfs, cgi_entries }) {
    const script = `
import sys, io, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, r'${DIOT_ROOT.replace(/\\/g, '/')}')
from skills.cross_elf import build_cross_elf_model
m = build_cross_elf_model(r'''${main_elf}''', [x.strip() for x in r'''${cgi_elfs}'''.split(',') if x.strip()], [], [x.strip() for x in r'''${cgi_entries}'''.split(',') if x.strip()])
print(json.dumps(m, ensure_ascii=False))
`
    const out = await runPython(['-c', script], DIOT_ROOT)
    let parsed
    try { parsed = JSON.parse(out.trim().split('\n').pop()) } catch { parsed = { raw: out.slice(0, 500) } }
    return { content: [{ type: 'text', text: JSON.stringify(parsed, null, 2) }], structured: parsed }
  },
}

// ---------- 工具 7：Neo4j 路径查询 ----------
const neo4jPaths = {
  name: 'diot_neo4j_paths',
  description: '把 taint 分析结果入库 Neo4j 并查询 source→sink 路径（动态发现入口）。返回路径列表，如 ssdpcgi_main→lxmldbc_system。',
  parameters: {
    [Kind]: 'Object',
    type: 'object',
    properties: {
      device: strParam('设备/项目名（对应 result 目录）', 128),
      binary: strParam('ELF 二进制路径（用于定位 taint 产物）', 1024),
    },
    required: ['device', 'binary'],
    additionalProperties: false,
  },
  meta: META,
  async execute({ device, binary }) {
    // 直接查已有 Neo4j 数据（cgibin 已入库）
    const script = `
import sys, io, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, r'${DIOT_ROOT.replace(/\\/g, '/')}')
from neo4j import GraphDatabase
d = GraphDatabase.driver('bolt://localhost:7687', auth=('neo4j', 'REPLACE_NEO4J_PASSWORD'))
with d.session() as s:
    rows = list(s.run("MATCH (a:Parameter)-[:PARAM_PASS*1..6]->(b:Parameter) WHERE b.func_name IN ['system','popen','lxmldbc_system','strcpy','sprintf'] RETURN DISTINCT a.func_name AS src, b.func_name AS dst, a.param_str AS sp LIMIT 60"))
    out = []
    for r in rows:
        out.append({'src': r['src'], 'dst': r['dst'], 'param': (r['sp'] or '')[:80]})
    # 只保留 *main 入口（动态 source 语义）
    mains = [o for o in out if o['src'] and o['src'].endswith('main')]
    print(json.dumps({'total_chains': len(out), 'entry_chains': mains}, ensure_ascii=False))
d.close()
`
    const out = await runPython(['-c', script], DIOT_ROOT)
    let parsed
    try { parsed = JSON.parse(out.trim().split('\n').pop()) } catch { parsed = { raw: out.slice(0, 500) } }
    return { content: [{ type: 'text', text: JSON.stringify(parsed, null, 2) }], structured: parsed }
  },
}

// ---------- 工具 8：taint 分析运行（真执行） ----------
const taintRun = {
  name: 'diot_taint_analyze',
  description: '真实运行 taint 分析流水线（danger 调用图+IDA 反编译 → taint LLM 逐条 → checkpoint 落盘）。长任务（每条调用 LLM），模型需确认执行。输出 taint_analysis.json 路径与处理条目数。',
  parameters: {
    [Kind]: 'Object',
    type: 'object',
    properties: {
      device: strParam('设备/项目名', 128),
      binary: strParam('ELF 二进制路径', 1024),
      callgraph: strParam('可选：调用图 JSON 路径（diot_callgraph 产物），不传则先跑 callgraph 阶段', 1024),
      stages: strParam('要跑的阶段（逗号分隔），默认 danger,taint', 256),
    },
    required: ['device', 'binary'],
    additionalProperties: false,
  },
  meta: { ...META, isReadOnly: false, isConcurrencySafe: false, requiresApproval: 'always' },
  async execute({ device, binary, callgraph, stages }) {
    const binName = binary.split(/[\\/]/).pop().replace(/[^\w.-]/g, '_')
    const outDir = ensureResultDir(device, binName)
    const stageList = (stages || 'danger,taint').split(',').map(s => s.trim()).filter(Boolean)
    const args = ['diot.py', binary, 'D:/AgentLearning/IOT Agent/firmware/rootfs', device, '--stages', stageList.join(',')]
    if (callgraph) args.push('--callgraph', callgraph)
    // 真跑流水线（长任务：每条 taint 调 LLM，最多 30 分钟）
    const stdout = await runPython(args, DIOT_ROOT, 1800000).catch((e) => `taint pipeline error: ${e.message}`)
    const structured = {
      device,
      binary,
      stages: stageList,
      status: 'executed',
      output: join(outDir, 'taint_analysis.json'),
      pipelineOutput: stdout.slice(-2000),
    }
    return { content: [{ type: 'text', text: JSON.stringify(structured, null, 2) }], structured }
  },
}

// ---------- 工具 9：分析产物读取 ----------
const readArtifacts = {
  name: 'diot_read_artifacts',
  description: '读取 Diot 分析产物（taint 结果 / 路径 / 报告 / 判定）。返回文件内容摘要。',
  parameters: {
    [Kind]: 'Object',
    type: 'object',
    properties: {
      device: strParam('设备/项目名', 128),
      binary: strParam('ELF 二进制路径', 1024),
      artifact: strParam('产物名：vul_result.txt / taint_analysis.json / neo4j_paths.json / cmd_injection_candidates.txt', 128),
    },
    required: ['device', 'binary', 'artifact'],
    additionalProperties: false,
  },
  meta: META,
  async execute({ device, binary, artifact }) {
    const binName = binary.split(/[\\/]/).pop().replace(/[^\w.-]/g, '_')
    const outDir = ensureResultDir(device, binName)
    const p = join(outDir, artifact)
    const text = artifact.endsWith('.json')
      ? JSON.stringify(readJsonSafe(p) ?? { notFound: p }, null, 2)
      : readTextHead(p)
    return { content: [{ type: 'text', text: text.slice(0, 12000) }], structured: { artifact, path: p, length: text.length } }
  },
}

// ---------- 工具 10：附件落盘（session-file:// → 真实文件） ----------
// 根因修复：AGH 附件是虚拟路径（session-file://<seq>/<n>），数据存在会话日志里，
// shell / ELF 分析工具无法直接使用。必须先用本工具把附件导出到真实磁盘。
const basename = (p) => String(p || '').split(/[\\/]/).pop().replace(/[^\w.\-]/g, '_') || 'attachment.bin'
const exportAttachment = {
  name: 'diot_export_attachment',
  description: '把会话附件（session-file://<seq>/<n> 虚拟路径）导出为真实磁盘文件，供 shell / ELF 分析使用。固件/ELF 分析前必须先调用本工具落盘：用 read session-file://list 找到附件引用 → 本工具导出到 destDir → 用返回的真实路径做后续分析。',
  parameters: {
    [Kind]: 'Object',
    type: 'object',
    properties: {
      path: strParam('会话附件引用，如 session-file://29/1（来自 session-file://list 或 user/message 附件）', 128),
      destDir: strParam('导出目标目录（绝对路径，自动创建）。默认 D:/AgentLearning/IOT Agent/firmware/attachments', 1024),
    },
    required: ['path'],
    additionalProperties: false,
  },
  meta: META,
  async execute({ path, destDir }, context) {
    try {
      if (!/^session-file:\/\/[1-9][0-9]*\/[1-9][0-9]*$/u.test(path)) {
        return { isError: true, content: [{ type: 'text', text: 'path 必须是 session-file://<seq>/<n> 格式，先 read session-file://list 查看可用附件。' }] }
      }
      if (!context?.session?.readAttachment) {
        return { isError: true, content: [{ type: 'text', text: '当前运行时无 readAttachment 能力，无法导出附件。' }] }
      }
      const file = await context.session.readAttachment({ path })
      if (!file) {
        return { isError: true, content: [{ type: 'text', text: `附件不可用：${path}（可能已不在当前会话）。用 read session-file://list 查看。` }] }
      }
      const dir = destDir ? resolve(String(destDir)) : 'D:/AgentLearning/IOT Agent/firmware/attachments'
      mkdirSync(dir, { recursive: true })
      const name = basename(file.name || 'attachment.bin')
      const outPath = join(dir, name)
      const fs = await import('node:fs/promises')
      await fs.writeFile(outPath, Buffer.from(file.bytes))
      const text = JSON.stringify(
        { exported: true, name, mimeType: file.mimeType, sizeBytes: file.bytes.byteLength, savedPath: outPath },
        null, 2,
      )
      return { content: [{ type: 'text', text }], structured: { exported: true, name, mimeType: file.mimeType, sizeBytes: file.bytes.byteLength, savedPath: outPath } }
    } catch (error) {
      return { isError: true, content: [{ type: 'text', text: `附件导出失败: ${String(error?.message ?? error).slice(0, 500)}` }] }
    }
  },
}

// ---------- 插件入口 ----------
export const iotPlugin = {
  inject: ['extension'],
  apply(ctx) {
    const agnes = ctx.extension()
    for (const tool of [elfInfo, callgraph, sourceDiscovery, sinkScan, verify, crossElf, neo4jPaths, taintRun, readArtifacts, exportAttachment]) {
      agnes.registerTool(tool)
    }
    agnes.on('session_start', () => {
      agnes.ctx.log.info('Diot IoT plugin loaded: 10 tools registered (elf/callgraph/source/sink/verify/cross-elf/neo4j/taint/artifacts/export-attachment)')
    })
  },
}
