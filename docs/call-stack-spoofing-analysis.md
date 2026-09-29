# Analyse d'intégration : call stack spoofing (G3)

> Branche : `feat/call-stack-spoofing` — analyse, puis implémentation P1
> (fragment `templates/fragments/stack_spoof.rs`, flag `--stack-spoof`).
> Date : septembre 2026. Sources : VulcanRaven/namazso, LoudSunRun, Draugr (NtDallas),
> ThreadStackSpoofer (mgeeky), trampoline enum-callback CET-compliant (MrTiz, 2025),
> règles Elastic "Stack Spoofing via ROP Gadget", Eclipse (klezVirus), rust_syscalls (fork Nariod).

## 1. Problème

Les EDR modernes capturent la pile d'appels du thread au passage en kernel (entrée de
syscall, callbacks kernel, ETW-Ti) et la déroulent (`RtlVirtualUnwind`). Un frame dont
l'adresse de retour pointe dans une région privée/non adossée à un module est un IOC
classique ; plus subtilement, ils valident la **plausibilité de la chaîne d'appels** :
quel module a déclenché `NtAllocateVirtualMemory` ?

### Ce que voit un EDR aujourd'hui avec sysCRT / sysFIBER

Le mode `_INDIRECT_` de rust_syscalls est propre pour l'instruction `syscall` elle-même :
`do_syscall` positionne les registres puis fait `jmp rcx` vers l'instruction `syscall`
dans le stub ntdll (`ZwXxx + 0x12`). Aucun frame ntdll falsifié, adresse d'exécution du
`syscall` légitime.

En revanche, la chaîne d'adresses de retour au-dessus reste crue :

```
ntdll!ZwAllocateVirtualMemory+0x12   (instruction syscall, légitime)
payload.exe!inject_shellcode+X        (retour du call à do_syscall)
payload.exe!main
kernel32!BaseThreadInitThunk
ntdll!RtlUserThreadStart
```

Le loader est un PE sur disque (backed), donc pas d'unbacked-memory IOC à ce stade —
mais la séquence `NtOpenProcess → NtAllocateVirtualMemory RW → NtWriteVirtualMemory →
NtProtectVirtualMemory RX → NtCreateThreadEx` est directement **attribuée** au binaire
non signé `payload.exe`, dans ses propres fonctions. Le stack spoofing vise à remplacer
cette attribution par une chaîne plausible adossée à des modules Microsoft signés.

### Périmètre

- Couvre : les appels sensibles **de la phase loader** (avant exécution du shellcode).
- Ne couvre pas : les appels effectués par le shellcode lui-même une fois exécuté
  (problème du beacon — sleep obfuscation / spoofing au repos, hors scope G3).

## 2. Techniques candidates

| # | Technique | Principe | Détection connue | CET | Effort |
|---|-----------|----------|------------------|-----|--------|
| A | Ret-addr spoofing (VulcanRaven, LoudSunRun) | Trampoline asm remplace l'adresse de retour par un gadget `jmp [rbx]` d'un module signé ; rbx pointe une struct de fixup ; frames faux au-dessus (`BaseThreadInitThunk+0x14`, `RtlUserThreadStart+0x21`) | Elastic : règle "ret-addr non précédé d'un call + jmp REG" ; Eclipse (klezVirus) : même heuristique | Incompatible (shadow stack) | Moyen |
| B | Stack synthétique complète (Draugr, SilentMoonwalk) | Écriture de frames entièrement fabriqués, tailles de frame calculées depuis `.pdata` | Signatures sur les patterns d'unwind ; lecture de `.pdata` elle-même détectable ; chaîne invérifiable si les liens ne sont pas plausibles | Incompatible | Élevé |
| C | Trampoline enum-callback CET-compliant (MrTiz, 2025) | Exécution via worker thread pool → fonction enum légitime (`EnumSystemLocalesEx`…) → callback → syscall ; la pile résulte d'appels **réels**, jamais d'écriture d'adresses synthétiques | Quasi aucune : pas de ROP, pas de frame falsifié | **Compatible** | Élevé |
| D | Spoofing au repos (ThreadStackSpoofer) | Réécrit le dernier frame du thread dormant | Détectable (frames invalides au repos) | Incompatible | Moyen |

**Verdict** : B et D hors périmètre (B complexe et déjà signaturé ; D relève de la sleep
obfuscation, écart G4). C est l'état de l'art mais change le modèle d'exécution — c'est un
nouveau template, pas un fragment. A est le bon rapport valeur/effort pour un premier
livrable, avec deux mitigations : fallback silencieux si CET activé, et sélection
aléatoire du gadget pour casser les signatures.

## 3. Point d'ancrage technique dans rust_syscalls

Lecture du source de la crate (fork Nariod) — deux éléments publics déterminants :

```rust
// syscall_resolve.rs — public, résolution par hash djb2 via PEB, sans I/O
pub fn get_ssn(hash: u32) -> (u16, u64);   // (ssn, addr du syscall dans ntdll)

// syscall.rs — public, stub global_asm
extern "C" { pub fn do_syscall(ssn: u16, syscall_addr: u64, n_args: u32, ...) -> i32; }
```

Deux stratégies d'intégration :

1. **Wrapper autour de `do_syscall`** (réutilisation maximale) : le trampoline fabrique
   les faux frames puis saute sur `do_syscall`. Contrainte forte : `do_syscall` lit ses
   arguments à des offsets fixes (`[rsp+0x28]`, `[rsp+0x30]`…) — le trampoline doit
   reproduire exactement la disposition d'appel variadique sous les faux frames. Fragile
   : tout changement du stub de la casse.
2. **Stub autonome dans le fragment** (recommandé) : le fragment embarque son propre
   trampoline asm qui réplique le remuement de registres de `do_syscall` (~15
   instructions, SSN + adresse résolus via `get_ssn` public) puis saute directement à
   l'instruction `syscall` ntdll avec les faux frames en place. Zéro dépendance à la
   mécanique interne de la crate. Cohérent avec la philosophie des templates
   self-contained.

Outils Rust : `global_asm!` stable depuis 1.59 (aucune contrainte de toolchain, le
conteneur utilise `rust:slim` stable). Fragments x64 uniquement, garde `#[cfg(target_arch
= "x86_64")]` — le projet ne cible que `x86_64-pc-windows-gnu`.

## 4. Propositions

### P1 — Fragment `stack_spoof` (recommandée)

Nouveau fragment `templates/fragments/stack_spoof.rs` (même mécanique `include_str!`
que ETW/sandbox), embarquant :

1. **Résolution de gadget** : scan du `.text` de kernel32/ntdll pour `ff 23`
   (`jmp qword ptr [rbx]`), sélection aléatoire parmi les candidats (polymorphisme
   inter-builds), échec → `null`.
2. **Résolution des faux frames** : `kernel32!BaseThreadInitThunk+0x14` et
   `ntdll!RtlUserThreadStart+0x21` via les helpers existants de `templates/common.rs`
   (résolution par hash, panic-free).
3. **Détection CET** : `ntdll!IsProcessCETEnabled` ; si activé, désactivation du spoof
   (fallback silencieux, cohérent avec la ligne opsec "mieux vaut ne rien faire que
   rater bruyamment").
4. **Trampoline + fixup en `global_asm!`** : remplacer l'adresse de retour à `[rsp]`
   par le gadget, `rbx` → struct `{ fixup, retaddr_originel, rsp_originel, rbx_originel }`,
   empilement des faux frames, saut à l'instruction `syscall` ntdll. Le fixup (naked)
   restaure `rsp`/`rbx` et rend la main au loader.
5. **API générée** : `spoofed_syscall!("NtAllocateVirtualMemory", args…)` — même
   ergonomie que `syscall!`, fallback automatique vers `syscall!` si gadget ou frames
   non résolus ou CET actif.

Application : sysCRT (les 5 appels sensibles) et sysFIBER (alloc/write/protect).
Flag CLI `--stack-spoof`, éligibilité calquée sur `uses_indirect_syscalls()`.

- Effort : ~200 lignes de fragment + ~60 lignes de générateur/CLI.
- Résiduel assumé : règles Elastic/Eclipse peuvent qualifier le gadget (voir §5).

### P2 — Généralisation aux templates `nt`

Le même trampoline, appliqué aux appels `extern "system"` directs (ntCRT, ntFIBER,
ntAPC…) : spoof de l'adresse de retour avant le `call` vers l'export ntdll hooked. La
pile traversera le hook EDR userland avec des frames légitimes. Rentabilise le fragment
au-delà des 2 templates `sys`. En seconde étape uniquement, P1 doit d'abord faire ses
preuves.

### P3 — Template `sysEnumCallback` (complément, v2)

Exécution du shellcode via chaîne enum-callback CET-compliable (MrTiz) : couvre le
stack **à l'entrée du shellcode** — ce que P1 ne couvre pas (après `SwitchToFiber` /
thread start, le premier frame du shellcode est unbacked). C'est un travail de
template distinct, à chainer avec P1 pour une couverture complète. Non prioritaire :
le shellcode visé (beacon) gère lui-même son stack s'il implémente son propre
spoofing/sleep mask.

## 5. Risques et résiduels (honnêteté de couverture)

| Risque | Mitigation | Résiduel |
|---|---|---|
| Règles Elastic "jmp REG gadget" / heuristique Eclipse | Gadget choisi aléatoirement parmi N candidats à chaque build et à chaque exécution ; frames plausibles (BTIT/RUTS réels) | Détectable par EDR à heuristique mûre |
| CET / shadow stack (Windows 11) | `IsProcessCETEnabled` → fallback silencieux | Perte du spoof sur processus CET, sans alerte |
| Offsets `+0x14` / `+0x21` dépendants de la version | Résolution dynamique des fonctions, offsets constants documentés comme prévalents ; fallback si non résolues | Faible |
| Crash du trampoline (stack layout) | Fragment testé par désassemblage + exécution sur VM dédiée avant merge | Phase de validation obligatoire |
| Détection du scan de pattern (`ff 23`) en mémoire | Scan borné au `.text` de 2 modules, sans API (arithmétique pointeur) | Lecture mémoire a priori non télescopée par les EDR |

## 6. Plan de validation (prémisse du futur PR)

1. `cargo check/clippy -D warnings/test/fmt` sur les 3 crates + les 11 templates
   cross-compilés dans le conteneur podman.
2. Génération d'échantillons avec `shared/calc.raw` : `--execution syscrt --stack-spoof`
   et `--execution sysfiber --stack-spoof`, plus une DLL.
3. Désassemblage du trampoline dans le binaire généré (`objdump -d`) : vérifier
   l'absence de patterns superflus et la conformité ABI x64 (shadow space, alignement).
4. Exécution sur VM Windows (hors conteneur — à charge de l'opérateur) : validation
   comportementale + capture de pile (WinDbg `k`) avant/après spoof.

## 7. Recommandation

**P1 seul, en premier livrable.** Le fragment est borné (sysCRT + sysFIBER), la
philosophie opsec est respectée (panique impossible, fallback silencieux, échec =
dégradation gracieuse vers le comportement actuel), et l'architecture des fragments
issue du refactoring PR #76 absorbe le changement sans toucher à la génération.
P2 et P3 ne s'ouvrent qu'après validation comportementale de P1 sur VM.
