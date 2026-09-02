# incident-v506-phase0-implementation - Track D v5.0.6 Phase 0 (OEM string synthesizer SCAFFOLDING)

> **Workflow-generated 2026-09-02** (5-lens adversarial pass + verify pipeline via .claude scripts). Findings + resolutions are inline.

Status: **Code-complete. Compila limpo `/W4 /WX` + assina.** Escopo estrito de instrumentacao (nenhum synthesizer code, nenhum descriptor extension, nenhum inventory). VM + bare-metal test pendentes.
Data: 2026-09-02
Driver: rstflt.sys v5.0.6 (Phase 0, novo marker version block no topo)
Escopo: implementacao da secao 6 row 1 + secao 7 counter list + secao 5 anti-patterns de [`../track-d-v506-oem-string-synthesizer-kickoff.md`](../track-d-v506-oem-string-synthesizer-kickoff.md).

---

## 1. Summary

Phase 2 de v5.0.5 mostrou byte-exact rewrite de `HardwareID` (substring engine encontrou os tokens do parent path — `Msft`/`Virtual_Disk` na VM, `Kingston`/`GPU` no bare-metal — e trocou por sinteticos FNV), MAS bareu ban #5 em ~11min de RubinOT porque os OEM string values (`DeviceDesc` "NVIDIA GeForce RTX 3070", `FriendlyName` "KINGSTON SA400S37480G", `Mfg` "(ASMedia,3.20,1.10)") nao compartilham substring nenhum com os tokens do parent path — o substring engine categoricamente nao pode alcanca-los. Ver [`incident-v505-phase2-ban-cleartext-oem-strings.md`](incident-v505-phase2-ban-cleartext-oem-strings.md) pro root cause detalhado.

A resposta arquitetural (kickoff §3) e um SYNTHESIZER independente por (device class, value name) que produz a string de substituicao a partir de seed + tokens do parent path (nao depende de substring com o value real). Landing esse synthesizer com sanity + hot-toggle + counters em uma unica PR seria ~1000+ LOC pra revisar de uma vez. Phase 0 quebra o landing: aqui so vai a instrumentacao (arm flag, counters, measure-first hooks, ring resize) que Phase 2 vai consumir. Nenhum synthesizer code, nenhum descriptor extension, nenhum inventory. Isso mantem cada PR pequena, permite ArmTrackD boot-validation isolada, e da uma janela pra medir se EMAC le `LocationInformation`/`LocationPaths`/`ContainerID` antes de gastar LOC em Phase 2 pra cobrir esses nomes.

Trocado em concreto:

- **Ring 16 -> 128 slots** — a janela forense de 16 slots wrappava em ~1.3s a taxa observada em Phase 2 (12 hits/s), o que zerava o ring durante os ~10 min ate o ban. 128 slots wrappam em ~11s de atividade continua, ainda bem dentro do 1 MB per-value cap (128 * 96 = 12288 bytes). `TrackDFlushWorker`'s on-stack `ringSnap` foi promovido a heap alloc (`NonPagedPoolNx`, tag `'FRDT'`) porque 12288 bytes excederia o budget de stack de ~12 KB.
- **9 `CallbackSynthHit_*` counters declarados** por (device class, value name): SCSI/PCI x (FriendlyName/DeviceDesc/Mfg) + USB/HID/BTH x FriendlyName. Todos static volatile LONG = 0, snapshotados + persistidos + drift-checked em `TrackDFlushWorker`. Zero-valued ate Phase 2 wirar os increments no synthesizer callback.
- **4 `CallbackSynth*Bail` counters declarados** — `TypeMismatchBail`/`OverflowBail`/`SizeSanityBail`/`InventoryMissBail`. Mesma treatment (declarados agora, bumped em Phase 2). Distingue os failure modes do synthesizer no diagnostic time.
- **3 `CallbackValHit_LocationInfo`/`_LocationPaths`/`_ContainerID` counters WIRED em Phase 0** — measure-first (kickoff §3.6). `TrackDHandlePostQueryValue` classifica o parent + confere o value name; se e gated caller (rubinot) + parent classificado + value name = uma das 3, bumpa o counter e retorna SEM invocar rewriter. Objetivo: se um counter fica em 0 apos um RubinOT session inteiro, o value name sai da Phase 2 target list.
- **`EnableValueSynth` REG_DWORD default 0** — arm flag do synthesizer path. Declarada, parseada em `LoadTrackDConfig` no boot, e hot-toggled via a extensao do `TrackDHandlePreSetValue` tap. Nao tem reader em Phase 0. Independente dos outros gates (`EnableRegCallback`, `EnableValueReadRewrite`, `EnableEdidValueRewrite`) pra permitir A/B testing em Phase 3 (substring rewriter armed sem synthesizer, ou vice versa).

Companion userland: `scripts/track-d-arm.ps1` ganha `-EnableSynth`/`-DisableSynth` + `-Diagnose` extendido com os novos counters + ring decoder derivado de `ring.Length / 96` (backward-compat com pre-v5.0.6 blob de 1536 bytes). `scripts/check-consistency.ps1` bloco Track D estendido do mesmo jeito.

---

## 2. Desvios deliberados do kickoff

### 2.1 `LastRingBufferSnapshot` periodic dumper DEFERIDO (redundante)

O kickoff §7 lista uma sugestao "nice to have" de um dumper periodico separado que gravaria snapshots do ring buffer em intervalos regulares (independente do drift check do `TrackDFlushWorker`). Analise pre-implementacao concluiu que isso e REDUNDANTE com o pipeline existente:

1. A causa raiz da janela forense zerada em Phase 2 era o SIZE do ring (16 slots wrappando em ~1.3s a 12 hits/s), NAO a cadencia do flush. Bumpando pra 128 slots o ring cobre ~11s de atividade continua, o que passa a ser suficiente pra pegar o burst de reads pre-ban.
2. O `TrackDFlushWorker` ja implementa uma drift-recheck loop (v5.0.0 finding #1) que re-queue a si mesmo se qualquer counter (incluindo `g_TrackDRingIndex`) drifta durante a janela de persist. Isso quer dizer que cada movimentacao do ring index ja triggera um flush independente da cadencia. Um dumper periodico separado so duplicaria writes sem widening a janela que o operator ve em `-Diagnose`.
3. Um dumper periodico adiciona um segundo path de write ao mesmo `HitRingBuffer` REG_BINARY, com potencial de race que agora precisaria de lock. O drift-recheck loop existente e strictly serial (uma so instance do work item), entao mantendo os writes por essa rota preserva a invariante de "one writer" que o design de v5.0.5 assume.

Re-evaluar so se um bare-metal RubinOT session em Phase 2 reproduzir o forensic-gap symptom com os 128 slots (i.e., o ring wrappou completamente entre o ultimo hit visivel no `-Diagnose` e o momento do ban, apagando a janela evidenciaria). Nesse caso a resposta e provavelmente bumpar o ring pra 256+ slots antes de adicionar um segundo path.

### 2.2 `ringSnap` stack -> heap

O kickoff §S2 explicitamente flags que 128 slots * 96 bytes = 12288 bytes excede o kernel worker-thread stack budget (~12 KB) uma vez que os outros locals do `TrackDFlushWorker` sao contabilizados. Fix: promove `ringSnap` a `NonPagedPoolNx` heap alloc via `ExAllocatePoolWithTag` (tag `'FRDT'`), com free em `out:`. `sizeof(ringSnap)` mudaria de "12288 bytes" (array) pra "8 bytes" (pointer) apos o refactor, entao todos os call sites foram atualizados pra `sizeof(g_TrackDRingBuffer)` (o backing array global). Grep confirmou zero `sizeof(ringSnap)` remanescente. Alloc failure e best-effort: skipa o ring persist pra essa pass; o drift check no `out:` re-queue no proximo publish hot-path. Todos os outros 15+ counters persistem normalmente mesmo se a alloc falhar.

### 2.3 `TrackDValueNameIsMeasureFirst` companion helper (kickoff §S5)

O kickoff sugere modificar `TrackDValueNameIsInteresting` pra deixar measure-first names passarem tambem. Implementado como um companion helper separado (`TrackDValueNameIsMeasureFirst`) + `TrackDValueNameIsInteresting` chama ele apos o loop de descriptor allow-list. Rationale: (a) mantem o teste de measure-first isolado pra `TrackDHandlePostQueryValue` re-usar sem ter que reprobar o array; (b) o custo e o mesmo (3 `RtlEqualUnicodeString` case-insensitive), so estruturado em uma funcao adicional; (c) o handler ja re-usa o helper na branch measure-first pra distinguir qual dos 3 counters bumpar. Sem overhead a mais.

### 2.4 Non-rubi measure-first names NAO contam separadamente

A analise do kickoff §S5 explicitamente noteia: measure-first names passam o pre-filter tambem no non-rubi path do handler; a chamada a `TrackDValueNameAllowed(pre->ValueName, desc->ValueNames)` REJEITA measure-first names (nao estao em nenhuma allow-list), entao o non-rubi caller que le LocationInformation apenas paga a classification cost + sai. Deliberadamente NAO tentamos atribuir non-rubi measure-first counts — dobraria a contagem (o counter measure-first ja e "gated so"), adicionaria complexity, e o volume de leituras de measure-first names por processos random no boot e baixo o suficiente pra ser irrelevante como perf hit. Documentado no comment inline do handler.

---

## 3. Arquitetura

- **`TrackDHandlePreSetValue`** ganha uma quarta branch pro `EnableValueSynth` name-match. Mesma shape que as 3 branches existentes (`EnableRegCallback`, `EnableValueReadRewrite`, `EnableEdidValueRewrite`) — `target = &g_TrackDValueSynthEnabled;` seguido pelo mesmo verify-parent-path + copy-value block. Sem novo path novo.

- **`TrackDHandlePostQueryValue`** ganha uma nova branch measure-first apos `desc == NULL` guard e ANTES do `TrackDValueNameAllowed` check. Se o value name e measure-first, bumpa o counter correspondente e RETORNA (nao dispatcha pro rewriter, nao bumpa `HitCount`, nao escreve ring buffer). Isso preserva a semantica do kickoff §3.6: "measure without rewriting".

- **`TrackDValueNameIsInteresting`** e amended pra tambem TRUE em measure-first names, entao a cheap pre-filter (uniao de todos os allow-lists) passa measure-first thru pra o parent classifier. Sem esse hook, measure-first names short-circuitariam no line 4547 antes de qualquer classificacao.

- **`LoadTrackDConfig`** ganha um terceiro `ZwQueryValueKey` block pra `EnableValueSynth` (mesmo shape que os dois v5.0.5 Phase 2 blocks). Sem side effect ate Phase 2 wirar o reader.

- **`ArmTrackD`** ganha 4 `RtlInitUnicodeString` calls novos: `g_TrackDEnableValSynthName` (pro tap), `g_TrackDValNameLocationInfo`, `g_TrackDValNameLocationPaths`, `g_TrackDValNameContainerID` (pras comparacoes measure-first).

- **`TrackDFlushWorker`**: 16 novos snapshot reads (9 SynthHit + 4 SynthBail + 3 measure-first), 16 novos `ZwSetValueKey` writes, 16 novos post-reads pro drift check, +16 novos comparison terms na if-chain do drift check. `ringSnap` refactorado de on-stack array pra heap alloc (`ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(g_TrackDRingBuffer), 'FRDT')`) freed em `out:`. Ring persist agora guarded por `if (ringSnap != NULL)` porque alloc failure e best-effort.

- **`TRACKD_RING_SIZE`** mudou de `16u` pra `128u`. `TRACKD_RING_MASK` recalcula automaticamente (power-of-two invariante mantido). Comment sobre `TRACKD_HIT_RECORD` layout atualizado pra "128 * 96 = 12288 bytes".

---

## 4. Pre-review self-checks

- **Build limpo** `/W4 /WX` (nenhuma warning nova, nenhum error). Toolchain: MSVC 14.51 via VS 2026 Community "VS 18". WDK 10.0.22621. Assinou via `signtool sign /sha1 30310EE7644799431FFF099E1194817E813152B9`. Marker regex `RstFlt-v\d+\.\d+\.\d+-BUILD-MARKER` presente (a version marker global nao mudou porque `/INCLUDE:RstFltVersion` continua apontando pro mesmo linkage symbol; a distincao Phase 0 vs Phase 1 vs Phase 2 fica so no changelog block header).
- **Changelog block v5.0.6** adicionado no TOPO da lista de changelog blocks (imediatamente antes do v5.0.5 block existente, que continua intocado). Header explicito "v5.0.6 - Phase 0 - OEM string synthesizer scaffolding + measure-first counters.".
- **ASCII compliance** — `scripts/track-d-arm.ps1` e `scripts/check-consistency.ps1` novos adds sao ASCII-only (nenhum em-dash, nenhum accent nas linhas novas). Prose Portuguese-BR nos blocos novos usa hifens regulares.
- **Sem Zw* no callback body** — `TrackDValueNameIsMeasureFirst` chama so `RtlEqualUnicodeString`. A branch measure-first em `TrackDHandlePostQueryValue` bumpa via `InterlockedIncrement` (nenhum Zw). Persistencia dos 16 novos counters continua via `TrackDFlushWorker` no `DelayedWorkQueue`, FORA do callback stack — mesma contract do resto de Track D.
- **Sizes em bytes, nao chars** — `RtlEqualUnicodeString` usa comparacao case-insensitive baseada em UNICODE_STRING (Length em bytes), so as macros de string sao WCHAR string literals passadas por `RtlInitUnicodeString`. Nenhum wchar count aritmetico introduzido.
- **Sem PagedPool alloc inside callback body** — a unica alloc nova (`ringSnap`) esta dentro de `TrackDFlushWorker`, que roda no `DelayedWorkQueue` a PASSIVE, fora do callback stack. Usa `NonPagedPoolNx` (spec § S2 preferencia; SDV nao warns).
- **grep confirmou** que nao ha outros `TRACKD_HIT_RECORD [...]` on-stack uses (so o global `g_TrackDRingBuffer[TRACKD_RING_SIZE]` na file scope).
- **PS parse OK** — `[System.Management.Automation.PSParser]::Tokenize` roundtrip zero-error em ambos os scripts.

---

## 5. Adversarial review findings (workflow `wf_d5efb1ac-507`, 5 lens agentes + verify pipeline)

Total: 4 findings surfaced por 5 lens agentes; 3 CONFIRMED, 1 REFUTED por verify pass. Detalhes:

| # | Lens | Sev | Arquivo | Summary | Verify | Fix outcome |
|---|------|-----|---------|---------|--------|-------------|
| 1 | backward-compat | LOW | scripts/check-consistency.ps1:316 | Hint operator "ver ring buffer (last 16 hits)" ficou stale pos ring 16 -> 128; sub-reporta janela forense em 8x. | **CONFIRMED** | **APPLIED** — trocado por "last N hits: 128 em v5.0.6+, 16 em pre-v5.0.6". String fixa em vez de derivar de `$totalSlots` porque a linha renderiza mesmo se blob nao for lido. |
| 2 | backward-compat | LOW | driver/rstflt.c:4769 | "Measure-first counters wire unconditionally com EnableValueReadRewrite=1; nao sao gated by EnableValueSynth." | **REFUTED** | N/A — sentinel checklist claimed pelo reviewer nao existe na tree; a spec explicitamente diz "measure-first counters WIRED em Phase 0" independente de EnableValueSynth (que nao tem reader ainda). Behavior atual e o desejado. |
| 3 | (unlabeled) | LOW | driver/rstflt.c:5074 | "HitRingBuffer skipped on pool-alloc failure while every other counter still flushes" — inconsistencia entre alloc-fail behavior e drift check. | **CONFIRMED** | **WON'T FIX (deferido)** — reviewer explicitly qualified como "Optional / Not urgent / Consideration". Fix (alloc permanente de 12288 bytes NonPagedPoolNx com lifetime plumbing atraves de ArmTrackD + unarm/unload path) e arquitetural, nao minimal edit; interage com invariante `g_TrackDFlushQueued` CAS + libera path. Trigger (starvation de 12288 bytes NonPagedPoolNx em Windows box vivo) e nearly theoretical. Best-effort skip-on-alloc-fail ja documentado em codigo (rstflt.c:4919-4922 + :5079). Reevaluate se VM cycle ou bare-metal test showar sintomas relacionados. |
| 4 | performance | LOW | driver/rstflt.c:4730 | "Pre-filter now admits LocationInformation/Paths/ContainerID, adding a CmCallbackGetKeyObjectID walk per system-wide read unless caller is rubi." | **CONFIRMED** | **APPLIED** — early return `if (TrackDValueNameIsMeasureFirst(pre->ValueName)) return STATUS_SUCCESS;` adicionado no non-rubi branch de `TrackDHandlePostQueryValue` (rstflt.c:4745) ANTES do `CmCallbackGetKeyObjectID` walk. Remove cost do key-object walk + parent classify pra non-rubi callers em measure-first names. Gated branch intacto — measure-first counters continuam bumpando exatamente pros rubi callers. Post-review nit adicionado ao changelog block. |

Post-review build re-confirmed: cl.exe /W4 /WX limpo, signtool sign OK, rstflt.sys = 61712 bytes (BUILD-MARKER bumped `v5.0.5` -> `v5.0.6` off-workflow como polish adicional apos deteccao humana; nao surfaced pelo review workflow — nenhum dos 5 lens agentes anchora contra marker consistency).

---

## 6. Open questions

1. **Qual measure-first counter, se non-zero, escalava Phase 1 scope?** Hipotese: se `CallbackValHit_LocationInfo` > 0 depois de uma RubinOT session, e forte sinal que EMAC le `LocationInformation` como parte do fingerprint de dispositivo — Phase 1 precisa entao promover `LocationInformation` de measure-first pra rewriter row. Se todos 3 ficam em 0, os 3 saem da target list e Phase 2 foca so em `DeviceDesc`/`FriendlyName`/`Mfg`.
2. **Estimativa de LOC do Phase 2 synthesizer com esse scaffolding em place?** Fora do escopo do Phase 0, mas a decomposicao Phase 0 (scaffolding pronto: counter set + arm flag + measure-first hooks + ring resized) reduz Phase 2 pra: (a) extensao de `TRACKD_VALUE_DESCRIPTOR` com um `Synthesizer` field, (b) 3 synthesizer callbacks (SCSI/PCI/BTH — USB/HID partilham parent-token semantics com BTH), (c) inventory header (uma tabela por (class, value_name) -> pool de synth strings selecionadas por FNV-of-parent-tokens). Estimativa preliminar: ~500-800 LOC C, ~2-3 lens de review, 3-5 dias inclusive VM sanity + bare-metal test. Melhor estimativa depende de quanto Phase 1 (PCI sub-classification por class-code) reduz o tamanho da inventory.

---

## 7. Files touched

Ver a saida structured do implementer (JSON com path + summary + LOC).
