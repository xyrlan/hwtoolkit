# incident-v505-phase1-implementation - Track D v5.0.5 Phase 1 (BTH + STORAGE\Volume + descriptor-table refactor)

Status: **CODE COMPLETE + ADVERSARIAL REVIEW CLEAN (2026-09-01). VM SANITY + BARE-METAL PENDING.** Compila limpo sob `/W4 /WX`, assina OK, marker `RstFlt-v5.0.5-BUILD-MARKER`. Review multi-lens (5 lentes) retornou zero findings. Falta: rodar `scripts/phase1-sanity-test.ps1` no checkpoint `clean-v505-phase0-armed` e criar `clean-v505-phase1-armed`.
Data: 2026-09-01
Driver: rstflt.sys v5.0.5 (Phase 1; mesma marker version que Phase 0)
Escopo: implementacao das secoes 4.1/4.2/4.3 de [`../track-d-v505-value-handler-kickoff.md`](../track-d-v505-value-handler-kickoff.md).

---

## 1. Summary

Phase 1 entrega tres coisas (kickoff sec 4):

1. **Descriptor-table refactor** (sec 4.1, pre-requisito estrutural pro Phase 2). O `TrackDClassifyParent` if/else + os dois `switch(pathType)` dentro de `TrackDHandlePostEnumerate` (child gate + per-path counter) viraram uma unica tabela `g_TrackDDescriptors[]` de linhas `{PathType, Label, MatchParent, ChildGate, SynthName, ValueRows(NULL), ValueRowCount(0), HitCounter}`. Adicionar um path type agora e uma linha + tres callbacks pequenos. Os matchers e gates sao wrappers finos que preservam os predicados EXATOS do v5.0.1 - zero mudanca de comportamento pros 6 tipos existentes (SCSI/PCI/USB/HID/AudioR/AudioC).

2. **BTH rewriter** (sec 4.2). Parent suffix `\Enum\BTH`, leaf `Dev_XXXXXXXXXXXX` (Dev_ + 12 hex = BD_ADDR de 6 bytes). Reescreve os 12 hex via `FNV(seed + real-hex-bytes, "BTH_DEV|")`, preserva `Dev_`, same-wchar-count. Counter `CallbackHit_BTH` (era reservado em Phase 0, agora WIRED via a linha da tabela).

3. **STORAGE\Volume rewriter** (sec 4.3). Parent suffix `\Enum\STORAGE\Volume`, leaf `{GUID}#offset`. Reescreve so os 32 nibbles do GUID via `FNV(seed + real-38-GUID-bytes, "STORAGE_VOL|")`, preserva chaves/dashes/`#`/offset byte-exato. Counter `CallbackHit_Storage` (idem WIRED).

Bonus: **hardening de bug latente** (copy-first em todos os synths) + **`TrackDRewriteGuid32InPlace`** extraido do synth de Audio (byte-a-byte identico) e reusado pelo STORAGE\Volume.

---

## 2. Descriptor-table - por que agora e nao em Phase 2

Phase 2 (value-read handler) adiciona ~14 value rows por parent. Fazer o refactor em Phase 1 (so 2 tipos novos) e muito mais barato que faze-lo carregando 14 rows. A struct ja tem os slots `ValueRows`/`ValueRowCount` (NULL/0 agora); Phase 2 so preenche as rows sem re-tocar a definicao da struct nem o loop de dispatch.

Contrato dos callbacks (mesmas regras de reentrancy do resto do Track D - PASSIVE_LEVEL, sem Zw*, memory-only):
- `MatchParent(parent)` -> TRUE sse a linha e dona do parent.
- `ChildGate(realName, realWchars)` -> TRUE sse o leaf e candidato a rewrite.
- `SynthName(realName, realWchars, outName)` -> preenche outName (mesmo wchar count); **deve copiar real->out como primeiro ato** (invariante copy-first, ver sec 4).

`TrackDClassifyParent` agora tem assinatura `(parent, const TRACKD_PATH_DESCRIPTOR **outDesc)`: retorna o `TRACKD_PATH_TYPE` E o descriptor dono, entao o handler chega no gate/synth/counter sem segundo lookup. O branch name-miss chama com `outDesc=NULL` (so precisa do tipo pra bumpar `CallbackNonRubiParentMatch`).

---

## 3. Adversarial review (workflow multi-lens, pre-commit)

Seguindo a pratica documentada no changelog do Phase 0 ("4-lens workflow pre-commit"), rodei um workflow de review com 5 lentes independentes sobre o diff, cada uma retornando findings estruturados, com verificacao adversarial (refutar) de cada finding que aparecesse:

1. **behavior-preservation** - os 6 tipos v5.0.1 tem comportamento identico pos-refactor? (predicados de matcher/gate, wiring de counter, ordem da tabela).
2. **memory-safety / BSOD** - bounds de todo `realName[i]`, invariante copy-first, USHORT cast, deref de function pointer, `buf[192]`.
3. **new-pattern-logic** - BTH (Dev_ + 12 hex) e STORAGE\Volume (GUID rewrite + offset-zero); casos de `TrackDStorageOffsetIsZero`.
4. **byte-compat / determinism** - `TrackDRewriteGuid32InPlace` reproduz byte-a-byte o synth de Audio original? same-wchar-count em todos os synths.
5. **compile-and-contract** - forward decls, assinaturas de function pointer, unused symbols, `C_ASSERT`, ordem de definicao.

Resultado: **5 lentes, 0 findings** (88 tool calls + 589K tokens no total - engajamento real, nao empty-por-falha; journal confirma `{"findings":[]}` schema-valido em cada). Cruzado com o compile limpo `/W4 /WX` (2x) + verificacao manual do wiring da tabela, invariante copy-first, byte-compat do helper GUID, e a logica offset-zero.

---

## 4. Hardening de bug latente - copy-first

O synth de Audio v5.0.1 (`TrackDBuildSyntheticAudioGuid`) retornava cedo ANTES do `RtlCopyMemory(out, real)` quando o dash estava errado. O dispatch v5.0.1 setava `childOk=TRUE` sempre que `realWchars==38 && real[0]=='{' && real[37]=='}'` (SEM checar dashes), entao um leaf de 38 wchars com chaves mas dash ruim teria: childOk=TRUE, synth nao-inicializado (early return), writeback escrevendo **stack buffer nao-inicializado** de volta pro caller. Inalcancavel na pratica (leaves de MMDevices sao sempre GUIDs canonicos), mas agora **impossivel por construcao**: todo synth copia real->out como primeiro ato, entao qualquer bail de shape vira pass-through valido. Aplicado a Audio, BTH, e STORAGE\Volume.

---

## 5. Descoberta empirica - shape real de STORAGE\Volume (corrige premissas do kickoff)

Inspecionei o registry REAL de um host Win10 (2026-09-01, `Get-ChildItem Enum\STORAGE\Volume`). Duas correcoes as premissas do kickoff sec 4.3:

**5.1 Dois shapes coexistem:**
- Discos fixos: `{21c67967-a16b-11f1-a7a1-806e6f6e6963}#0000000000100000` - shape `{38-GUID}#hexoffset`, GUID no inicio. **O gate matcha.**
- Removiveis/USBSTOR: `_??_USBSTOR#Disk&Ven_SanDisk&Prod_Ultra_Fit&Rev_1.00#4C53...&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}` - GUID no FIM. O gate exige GUID no index 0, entao esses viram **pass-through no-op seguro** (storage removivel nao reescrito).

**5.2 "Boot volume == offset zero" e empiricamente FALSO.** O volume de sistema/boot fica em offset `0x100000` (1MB), NAO zero. Logo o bail offset-zero (`#0`, `#0x0`, tudo-zero) NAO singulariza o boot volume - em hardware real todo volume front-GUID fixo, incluindo o de sistema, e reescrito.

**Isso e SEGURO** e nao mudei o codigo por causa disso, porque o rewrite do Track D e **nao-persistente**: muta so o buffer de RESULTADO do `NtEnumerateKey` do caller gated (rubinot), nunca o hive em disco. `\SystemRoot` e o boot real sao resolvidos pelo kernel fora de qualquer callback com contexto rubinot, entao ficam intactos. O bail offset-zero foi mantido como skip conservador (dispara so pra uma entrada genuinamente zero-offset, se existir). **Corrigi toda a documentacao** (changelog do driver, comentarios de constante/gate/synth, README) que antes afirmava a premissa errada "boot volume load-bearing pra \SystemRoot".

**Consideracao residual pro maintainer:** o GUID sintetico do STORAGE\Volume usa dominio FNV proprio (`STORAGE_VOL|`) e NAO casa com o spoof userland de volume-GUID (`spoof-volume-guid.ps1` / MountedDevices). Se EMAC cruzar STORAGE\Volume-name contra MountedDevices-value, isso e uma inconsistencia detectavel - reconciliar num follow-up (dominio/seed compartilhado, ou deixar o value handler do Phase 2 cobrir MountedDevices com o mesmo dominio).

---

## 6. Caveat empirico herdado do Phase 0

`reg query /s` sobre parents non-SCSI pode NAO gerar trafego `NtEnumerateKey` observavel (kernel Cm-view cache serve hot parents sem dispatch pro callback) - ver memoria `v505-plan-adversarial`. Logo um probe de VM pode mostrar `CallbackHit_BTH`/`CallbackHit_Storage`=0 mesmo com o code path estruturalmente identico ao SCSI (validado end-to-end). Por isso o `phase1-sanity-test.ps1` trata BTH/Storage delta>0 como **soft-warn** e SCSI regression delta>0 como **hard**. Exercicio real dos rewrites de nome vem de sessao RubinOT ou do value handler do Phase 2.

---

## 7. Test plan / proximos passos

1. VM: restaurar `clean-v505-phase0-armed`, uninstall v5.0.5-Phase0 -> install v5.0.5-Phase1 -> reboot -> `track-d-arm.ps1 -Enable` -> reboot.
2. VM: `scripts/phase1-sanity-test.ps1` - valida (a) counters BTH/Storage presentes, (b) SCSI regression delta>0 (dispatch pos-refactor OK), (c) inspeciona filhos reais de BTH/STORAGE\Volume da VM vs o gate, (d) sem BSOD.
3. VM: `track-d-arm.ps1 -Diagnose` + `check-consistency.ps1` - confirmar per-path counters + ring buffer decodam.
4. Checkpoint `clean-v505-phase1-armed`.
5. So depois: Phase 2 (RegNtPostQueryValueKey handler, kickoff sec 5) - o fix aritmeticamente dominante (~14 value patterns, ~93% dos ~16,317 RegQueryValue events/burst).

---

## 8. Deliverables desta sessao

- `driver/rstflt.c` v5.0.5 Phase 1: enum BTH/Storage, descriptor table, matchers/gates/synths, `TrackDRewriteGuid32InPlace`, `TrackDStorageOffsetIsZero`, changelog block, comment-accuracy fixes.
- `scripts/track-d-arm.ps1`: labels BTH/Storage de "reservado" -> ativo (decoder ja estava Phase-1-ready desde Phase 0).
- `scripts/check-consistency.ps1`: comentario 6->8 target parents.
- `scripts/phase1-sanity-test.ps1`: NOVO harness de VM (inspecao de shape real + regression SCSI).
- `README.md`: secao Track D com escopo Phase 1 + shape notes corrigidas.
- `CLAUDE.md`: linha Phase 1 nas Standard commands.
- `02-compilar-driver.bat`: label v5.0.4 -> v5.0.5 (staleness cosmetica).
