# incident-v505-phase2-implementation - Track D v5.0.5 Phase 2 (value-read handler)

Status: **VM-VALIDATED (2026-09-02). Code-complete + adversarial-review-clean-after-fixes + `phase2-sanity-test.ps1` PASSOU no dev VM (byte-exato). Checkpoint `clean-v505-phase2-armed` criado. Bare-metal PENDENTE.** Compila limpo `/W4 /WX`, assina, marker `RstFlt-v5.0.5-BUILD-MARKER`. 5-lens review = 6 confirmados (2 problemas distintos) + 2 pontos dismissados, TODOS corrigidos (§5).
Data: 2026-09-01
Driver: rstflt.sys v5.0.5 (Phase 2; mesma marker version que Phase 0/1)
Escopo: implementacao da secao 5 de [`../track-d-v505-value-handler-kickoff.md`](../track-d-v505-value-handler-kickoff.md) - o fix aritmeticamente dominante.

---

## 1. Summary

Phase 0/1 reescreviam NOMES de subchaves em `RegNtPostEnumerateKey`. O triage pos-ban ([`incident-v505-post-ban-triage.md`](incident-v505-post-ban-triage.md)) provou que EMAC **nunca enumera**: abre cada chave de dispositivo por nome exato (via SetupDi/CM_*) e le os VALORES (`HardwareID`, `CompatibleIDs`, ...) com `RegQueryValueEx`. Esses valores ainda retornavam os tokens REAIS (Ven/Prod/Rev/SUBSYS/BD_ADDR/GUID) - e um nome de subchave sintetico ao lado de um HardwareID real e um tell de ban MAIS forte que a fingerprint crua.

Phase 2 adiciona o handler `RegNtPostQueryValueKey` que reescreve o DATA do valor para casar com os sinteticos do name-side, byte-a-byte.

---

## 2. Desvios deliberados do kickoff (todos documentados no changelog do driver)

### 2.1 `RegNtPostGetValueKey` nao existe

O kickoff sec 5.1 lista duas notify classes: `RegNtPostQueryValueKey` + `RegNtPostGetValueKey`. **Nao ha `RegNtPostGetValueKey` no enum `REG_NOTIFY_CLASS`** (confirmado em `wdm.h`). `NtQueryValueKey` e a rota kernel TANTO do Win32 `RegQueryValueEx` QUANTO do `RegGetValue`, e aflora so como `RegNtPostQueryValueKey`. Essa unica classe cobre as duas do kickoff. `RegEnumValue` (-> `RegNtPostEnumerateValueKey`) e uma classe separada que o recon NAO implica (EMAC le por nome), deixada pra v5.0.6 se aparecer evidencia.

### 2.2 Tabela de value-descriptors SEPARADA (nao `ValueRows` na tabela de enum)

O kickoff sec 5.2 propoe estender cada `TRACKD_PATH_DESCRIPTOR` com `ValueRows`. Isso pressupoe um mapeamento 1:1 entre parents de enum e parents de value - que NAO vale: (a) os matchers de enum matcham a chave CONTAINER (`\Enum\SCSI` suffix), mas o value read acontece na chave leaf/instance varios niveis abaixo (`\Enum\SCSI\Disk&Ven_..\<instance>`), entao um suffix-match em `\Enum\SCSI` nao pega o leaf; (b) MachineGuid/ComputerName/CPU/EDID nao tem contrapartida name-side. Logo o value-side ganhou sua propria tabela `g_TrackDValueDescriptors[]` com matchers estilo "path CONTAINS `\Enum\SCSI\`". Os slots `ValueRows`/`ValueRowCount` que o Phase 1 reservou na tabela de enum ficam NULL/0 (design alternativo descartado; documentado).

### 2.3 Consistencia name<->value POR CONSTRUCAO

Cada token sintetico do value-side e derivado do MESMO token real (parseado do parent path do valor) via o MESMO dominio FNV que o name synth usa (`SCSI_VEN|`/`SCSI_PROD|`/`SCSI_REV|`, `PCI_SUBSYS|`/`PCI_REV|`, `BTH_DEV|`, `STORAGE_VOL|`). Mesmo dominio + mesmos bytes reais + mesmo comprimento => token byte-a-byte identico no nome da subchave enumerada E no data do valor. O kernel e DONO dessas superficies (userland Level A roda `--skip-disk`/`--skip-volume`/`--skip-usb`/`--skip-hid`), entao so importa a consistencia interna name<->value, nunca com um valor escrito por userland.

### 2.4 MachineGuid/ComputerName/Hostname/CPU FORA de escopo

O kickoff sec 5.2 lista essas rows. Mas userland Level A JA reescreve esses valores no registry (o `04b` sem `--skip` pra elas), entao `RegQueryValueEx` ja retorna o valor spoofado. O kernel reescreve-los de novo geraria double-spoof (FNV do kernel != valor do userland) e uma inconsistencia entre superficies. Deixados FORA: o kernel so cobre as superficies que userland NAO consegue corrigir (as chaves `\Enum\*` de propriedade do PnP manager).

### 2.5 USB/HID sem value row

O `HardwareID` de USB/HID (`USB\VID_&PID_&REV_`) NAO carrega serial - o serial vive so no device instance ID (superficie CM_Get_Device_ID, nao um valor de registry), fora do alcance de `RegNtPostQueryValueKey`. Incluir uma row USB/HID seria dead code. Documentado como candidato v5.0.6 (interceptar o instance-ID exige mecanismo diferente).

### 2.6 EDID atras de flag propria default-off

EDID e superficie value-only (sem name-side). O deployment recomendado ja spoofa EDID via userland (`spoof-edid-full.ps1`), entao um rewrite kernel colidiria (double-spoof). EDID fica atras de `EnableEdidValueRewrite` (default 0), EM CIMA do gate master `EnableValueReadRewrite`. Ativar so em deployment kernel-EDID-only. Alem disso o rewriter EDID so mexe no serial numerico (bytes 12-15) + descriptor 0xFF (serial ASCII) + recomputa o checksum (byte 127); DEIXA o nome 0xFC e o product code (sao identificadores de MODELO, nao de unidade; hex-izar um nome de monitor e por si anomalo) e nunca toca DTDs (bytes off,off+1 != 0) nem o 0xFD range-limits (quebraria o modo/timing).

---

## 3. Arquitetura

`RstRegistryCallback` ganha `case RegNtPostQueryValueKey`, gated por `g_TrackDValueRewriteEnabled`. `TrackDHandlePostQueryValue`:

1. Guards de `post->Status`/PreInformation. `!NT_SUCCESS(post->Status)` exclui `STATUS_BUFFER_OVERFLOW` (o size-probe da chamada dupla, cujo buffer nao esta populado).
2. Gate de image name PRIMEIRO (`_strnicmp "rubinot"` barato), entao so reads de rubinot pagam o custo de `CmCallbackGetKeyObjectID`. No miss, classifica o parent pro diagnostico non-rubi value (paridade com o Phase 0).
3. `CmCallbackGetKeyObjectID(pre->Object)` -> parent key path.
4. `TrackDClassifyValueParent` -> descriptor (SCSI/PCI/BTH/STORAGE/EDID).
5. `TrackDValueNameAllowed(pre->ValueName, desc->ValueNames)` (allow-list curada por superficie).
6. EDID double-gate.
7. `TrackDExtractValueData` decodifica `KEY_VALUE_*_INFORMATION` (Partial / PartialAlign64 / Full / FullAlign64; Basic e classes desconhecidas passam; regiao de data bounds-checked dentro de `pre->Length`).
8. `desc->Rewriter(...)` SEH-wrapped, in-place, same-length.
9. Instrumentacao: `g_TrackDHitCount` + `desc->HitCounter` (por superficie) + ring buffer (kind=value-gated).

### 3.1 Dois engines de rewrite (ambos same-length / in-place)

- **Substring neutralizer** (SCSI, BTH, STORAGE): snapshot do valor pristino em `orig[]` (cap `TRACKD_MAX_VALUE_BYTES`=2048; maior passa), acha cada token real no snapshot, escreve o token sintetico no offset correspondente no buffer vivo. **Scanear o snapshot (nao o buffer vivo) e o que torna o rewrite multi-token seguro** - um token hex sintetico nunca pode ser re-matchado como um token real (curto) posterior, porque o match-finding sempre ve os bytes originais. Floor `TRACKD_MIN_TOKEN_WCHARS`=3 bloqueia replace cego de tokens de 1-2 chars (colisao).
- **Marker-field rewriter** (PCI): pra cada marker `&SUBSYS_`/`&REV_`, reescreve o campo seguinte (ate `&`, `\`, NUL, ou fim) via o `TrackDFillTokenFnv` compartilhado (campo real snapshotado antes da escrita). Marker-anchored, entao o REV de 2 hex e seguro; VEN_/DEV_ (chaves de bind PnP) preservados.

---

## 4. Adversarial review (workflow multi-lens, pre-commit)

Seguindo a pratica do Phase 0/1, rodei um workflow de review com 5 lentes independentes sobre o diff do driver, cada uma retornando findings estruturados, com verificacao adversarial (refutar cada finding) num segundo estagio:

1. **bounds / BSOD** - todo index de array e pointer add em `TrackDExtractValueData`, `dataPtr`, os loops de `TrackDReplaceWideTokenAll`/`TrackDValueMarkerFieldRewrite`, os parse loops de SCSI/BTH/STORAGE sobre o parent path, e os acessos fixos de 128 bytes + descriptor do EDID.
2. **same-length invariant** - todo rewriter preserva o comprimento exato em bytes; NULs de MULTI_SZ; DataLength/ResultLength nunca tocados.
3. **name<->value consistency** - sinteticos value-side byte-a-byte == name-side (dominio FNV, seed, bytes reais UTF-16LE, round byte); hazard de re-read in-place do marker-field.
4. **callback contract / reentrancy / gating** - sem Zw* no path; gating dos flags; tap de 3 flags; ordem do gate; drift-recheck symmetry dos counters novos; kind byte do ring.
5. **logic / EDID / classification** - deteccao display-descriptor vs DTD, checksum, offsets; SCSI evita CdRom&Ven_; EDID exige DISPLAY marker + `\Device Parameters` suffix; extract rejeita Basic + zero-length; success-check exclui BUFFER_OVERFLOW.

Resultado: **5 lentes, 20 agentes, 15 findings crus -> 6 CONFIRMED / 9 FALSE_POSITIVE / 0 UNCERTAIN** (2.34M tokens, 159 tool calls). Os 6 confirmados colapsam em DOIS problemas distintos (5 lentes independentes acharam o mesmo Issue A; 1 lente achou Issue B). O unico finding cru rotulado "high" era outra copia do Issue A. Ver secao 5.

---

## 5. Findings triados + fixes aplicados

Os 6 confirmados = 2 problemas reais + 2 pontos de design dismissados-mas-acionados. TODOS corrigidos (recompilado limpo `/W4 /WX` + assinado).

**Issue A (MEDIUM, 5 lentes) - floor name<->value desincronizado.** O value rewriter de SCSI floora tokens Ven/Prod/Rev curtos (< `TRACKD_MIN_TOKEN_WCHARS`=3) porque um substring-replace cego de 1-2 chars colidiria. Mas o name synth `TrackDBuildSyntheticName` NAO tinha floor - reescrevia tokens de qualquer tamanho >= 1. Logo um disco com vendor de 2 chars ("HP", "LG", "SK") ou revision de 1-2 chars ("0", "A0", "10") teria o NOME da subchave sintetico mas o VALOR real - exatamente o tell de ban que o Phase 2 existe pra remover. Latente na VM (Msft/Virtual_Disk/1.0 todos >= 3). **Fix**: aplicar o MESMO floor >= 3 em `TrackDBuildSyntheticName` (Ven/Prod/Rev), entao os dois lados pulam tokens curtos em lockstep (um token de 1-2 chars, baixa entropia de qualquer jeito, fica real em AMBOS). Sem efeito pra tokens >= 3 (o caso comum; os vetores byte-exatos validados continuam batendo).

**Issue B (LOW, 1 lente) - clobber order-dependent no substring de SCSI.** As tres passadas sequenciais all-occurrence sobre o snapshot podiam deixar um token posterior (Prod) sobrescrever o synth de um anterior (Ven) onde um aninhava no outro (Ven prefixo de Prod). **Fix**: `TrackDValueRewriteScsi` agora faz uma unica varredura LONGEST-MATCH esquerda->direita sobre o snapshot - a cada posicao escolhe o token mais longo que casa e pula alem dele, entao cada byte e reivindicado por exatamente um token (o mais especifico), casando a semantica per-field do name side. (O unico caso irresoluvel e dois campos DISTINTOS com bytes identicos - ex. Ven == Prod - que substring matching nao consegue desambiguar; degenerado, nao visto em hardware real.)

**Ponto C (PERF, dismissado como non-defect mas acionado).** O branch non-rubi do diagnostico value chamava `CmCallbackGetKeyObjectID` (walk do key object) em TODO `NtQueryValueKey` do sistema enquanto armado - o caminho de registry mais quente. **Fix**: um pre-filtro barato de value-name (`TrackDValueNameIsInteresting`, uniao dos allow-lists) roda ANTES do key-object walk e do image-name gate, entao so leituras de um value name fingerprint (HardwareID/EDID/...) pagam o custo. Diagnostico non-rubi preservado, custo cortado ~ordens de magnitude.

**Ponto D (dismissado como inert mas acionado) - simetria zero-offset STORAGE.** O name side pula GUID de volume zero-offset (skip conservador); o value side nao. **Fix**: `TrackDValueRewriteStorage` agora espelha o skip zero-offset (`TrackDStorageOffsetIsZero`), entao um volume zero-offset (degenerado) fica real em nome E valor. Inerte em hardware real (volume de sistema em offset 0x100000) mas remove a assimetria.

Os 9 FALSE_POSITIVE foram verificados adversarialmente (cada finding passou por um agente instruido a REFUTAR, default FALSE_POSITIVE); inclui variantes redundantes dos acima e observacoes de assimetria sem defeito observavel concreto (as duas que acionei mesmo assim, C e D, por baixo custo + correcao).

---

## 6. Instrumentacao nova

- `CallbackValHit_SCSI/_PCI/_BTH/_Storage/_Edid` (REG_DWORD): engagement = parent + value name matcharam e o rewriter rodou. E no-op quando o valor nao carrega o token (o proprio diagnostico pra BTH/STORAGE - se ficam 0 apos sessao real, esses valores nao vazam o token, so o instance-ID vaza).
- `CallbackNonRubiValueMatch` (REG_DWORD): processo non-rubi leu um value alvo.
- Ring buffer reusado: o campo `WasGated` virou um kind byte {0 enum-nonrubi, 1 enum-gated, 2 value-gated, 3 value-nonrubi} - sem mudanca de tamanho da struct/decoder (C_ASSERT 96 intacto).
- Decoders atualizados: `track-d-arm.ps1 -Diagnose` + `check-consistency.ps1` bloco Track D.

---

## 7. Config / boot safety

- `EnableValueReadRewrite` (REG_DWORD, default 0): gate master do value handler. Default OFF no boot - um bug nesse handler durante a tempestade de value-reads do boot (LSA/Winlogon) daria brick.
- `EnableEdidValueRewrite` (REG_DWORD, default 0): gate separado do EDID.
- `TrackDHandlePreSetValue` agora tapa os TRES enable values (era so `EnableRegCallback`), entao `track-d-arm.ps1 -EnableValueRewrite`/`-DisableValueRewrite` hot-toggla sem reboot.

---

## 7b. VM cycle result (2026-09-02) - PASSOU

Rodado no dev VM via PowerShell Direct (host-driven). Base: `clean-no-driver` -> install do zero (03) -> arm (-Enable) -> reboot LIMPO -> `-EnableValueRewrite` -> `phase2-sanity-test.ps1`. Resultado **PASS byte-exato**:

- Disco alvo (Hyper-V): `Disk&Ven_Msft&Prod_Virtual_Disk`. Ven="Msft", Prod="Virtual_Disk" (sem `&Rev_` na subchave).
- Synth esperado pela recipe PS: Ven `Msft`->`FDF2`, Prod `Virtual_Disk`->`F381B244E994`.
- GATED (`rubinot_probe.exe query .. /v HardwareID`) value data: `SCSI\DiskFDF2____F381B244E994____1.0_ | ...` - **real "Msft"/"Virtual_Disk" AUSENTES do data, synth presentes, byte-exato vs a recipe** (que por sua vez bate com o `TrackDFillTokenFnv` do kernel compilado como user-mode). Consistencia name<->value provada.
- NON-GATED (`launcher_probe.exe`): value data com "Msft"/"Virtual_Disk" reais - gate discrimina.
- `CallbackValHit_SCSI` incrementou; hive inalterado (308 bytes, non-persistent + same-length).
- Boot COM value-side armado (`EnableValueReadRewrite=1` persistido) validado: `InvokeCount=22,946,590` (23M invocacoes de callback no boot+operacao), **0 minidumps / 0 BSOD**, driver RUNNING, `LastArmStatus=0x00`. Valida o boot path do §6.2 step 6.
- Ring buffer + pre-filtro (Ponto C) confirmados vivos: `RuntimeBroker` lendo `Storage`/`HardwareID` gravado como kind `v/no` (value-side non-rubi), provando o `TrackDValueNameIsInteresting` deixando so nomes fingerprint passarem.

**Licao operacional CRITICA (nova, salva em CLAUDE.md):** com KVP+Heartbeat desabilitados, `Restart-VM`/`Stop-VM` do host = shutdown SUJO (Kernel-Power 41) que NAO faz flush da hive SYSTEM -> o `sc create`/UpperFilters/Parameters recem-escrito (ou removido) faz ROLLBACK pro ultimo flush enquanto o `.sys` (NTFS) persiste. Causou (a) "service some apos install" e (b) o Automatic Repair pos-uninstall (UpperFilters aponta pra RstFlt cujo .sys sumiu -> 0x7B), ambos falsamente parecendo bug do driver. **Fix: rebootar o guest de DENTRO via `shutdown /r /t 5 /f`** (shutdown limpo do OS faz flush). Automacao do ciclo via PowerShell Direct requer `LimitBlankPasswordUse=0` no guest (default 1 bloqueia logon de rede com senha branca).

**Refinamento do harness** (feito no mesmo ciclo): `phase2-sanity-test.ps1` agora checa o real/synth SO no DATA do valor (nao no key-path que o `reg.exe` ecoa - esse contem o instance-ID real `Disk&Ven_Msft..`, que o value handler nao reescreve, so o name-side quando enumerado). O contador `CallbackValHit_*` virou criterio SOFT (zera em memoria no reboot enquanto o registro guarda o valor pre-reboot + flush async -> delta nao confiavel; a prova HARD e o value data sintetico).

**Residual conhecido confirmado no VM:** o `reg.exe` ecoa o key-path com o instance-ID real (`Disk&Ven_Msft&Prod_Virtual_Disk`) - o value handler reescreve o HardwareID (data) mas nao o instance-ID (superficie CM_Get_Device_ID, fora do alcance de RegNtPostQueryValueKey; name-side so cobre via enumeracao). Se EMAC cruza instance-ID vs HardwareID, isso e um tell - candidato v5.0.6 (instance-ID intercept). O bare-metal RubinOT test (§6.3 outcome tree) decide se importa.

## 8. Test plan / proximos passos

1. VM: restaurar `clean-v505-phase1-armed` (ou `clean-v505-phase0-armed`), uninstall -> install v5.0.5-Phase2 -> reboot -> `track-d-arm.ps1 -Enable` -> reboot -> `track-d-arm.ps1 -EnableValueRewrite`.
2. VM: probe `rubinot_probe.exe query HKLM\SYSTEM\CurrentControlSet\Enum\SCSI\<Disk&Ven_..>\<inst> /v HardwareID` - confirmar bytes sinteticos consistentes com o name synth; probe non-rubi do mesmo path -> valor real.
3. VM: `track-d-arm.ps1 -Diagnose` + `check-consistency.ps1` - confirmar `CallbackValHit_SCSI`>0, ring kind=v/YES, decoders OK, sem BSOD.
4. **Unit test userland** do engine de rewrite (harness que simula buffers `KEY_VALUE_*_INFORMATION`): REG_MULTI_SZ (empty/single-null/double-null/huge), EDID blocks reais com verificacao de checksum, extract de cada info class.
5. Checkpoint `clean-v505-phase2-armed`.
6. Bare-metal armed (single ship) so apos o VM cycle limpo. Fresh procmon capture antes de logar em RubinOT. Outcome tree do kickoff sec 6.3.

---

## 9. Deliverables desta sessao

- `driver/rstflt.c` v5.0.5 Phase 2: `RegNtPostQueryValueKey` handler, tabela de value-descriptors, 5 rewriters (SCSI/PCI/BTH/STORAGE/EDID), extractor + engines (substring snapshot + marker-field), 2 config flags + tap generalizado, counters + persistencia, changelog block.
- `scripts/track-d-arm.ps1`: `-EnableValueRewrite [-Edid]` / `-DisableValueRewrite` + `-Diagnose` decode dos value counters e ring kinds.
- `scripts/check-consistency.ps1`: bloco Track D estendido com value handler state + counters + ring kind breakdown.
- `docs/track-d-name-recipe.md`: addendum de consistencia value-side.
- `README.md` + `CLAUDE.md`: novos Parameters values + arm flags.
