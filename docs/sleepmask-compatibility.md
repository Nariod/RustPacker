# Compatibilité des templates RustPacker avec le sleep mask chiffré (specter-rs)

> Branche : `docs/sleepmask-compatibility`. Date : octobre 2026.
> Concerne le beacon [specter-rs](https://github.com/Nariod/specter-rs)
> (réécriture Rust de [Specter](https://github.com/0xC9H/specter) par 0xC9H),
> packé avec RustPacker — et la question : *mes templates ne provisionnent
> pas de mémoire RWX ; le masque de sommeil chiffré fonctionne-t-il quand
> même ?*

## 1. Réponse courte

**Oui — c'est un choix de conception, pas une luck.** Le masque de sommeil
de specter-rs n'a pas besoin que sa mémoire *soit* RWX au repos ; il a
besoin de pouvoir **changer lui-même les protections de ses propres
pages** via `NtProtectVirtualMemory` (syscall indirect). Or ce syscall
accepte de flapper n'importe quelle page **privée** allouée
(`NtAllocateVirtualMemory` / `VirtualAlloc[Ex]`), quel que soit son état
actuel — y compris `PAGE_EXECUTE_READ` à l'exécution, ce que font les
templates RustPacker avant de sauter dans le shellcode.

Une page RWX au repos serait même **contre-productive** : c'est un signal
EDR classique. Une allocation RX qui devient brièvement RW puis redevient
RX est plus discret.

## 2. Le mécanisme (specter-rs, `runtime/sleepmask.rs`)

Pour une image mappée RX au repos (cas RustPacker) :

```
flip RX -> RW (syscall indirect)  ->  keystream xorshift64 sur l'image
    ->  restore protection d'origine  ->  NtDelayExecution (image chiffrée
    pendant toute la fenêtre de sommeil)
wake -> flip RW -> re-keystream (XOR du même stream = déchiffrement)
    ->  restore RX  ->  reprise du beacon
```

- seules les **plages chiffrées** basculent ; la fenêtre du stub (le code
  qui dort et déchiffre) reste exécutable du début à la fin ;
- la protection d'origine est capturée par une **sonde au bootstrap** :
  flip de la page de queue, capture, restauration. Si le flip échoue
  (ex. section fichier mappée COW en lecture seule), le masque est
  **refusé** (`build_params` renvoie `None`) et le beacon dort en cycles
  simples, non chiffrés — **dégradation contrôlée, jamais de crash** ;
- détail terrain : la sonde flippe en **RWX, pas RW** — la page de queue
  contient du code vivant (layout `-Oz`), et un flip non exécutable
  plantait en `0xC0000005` sur la VM réelle ;
- le sommeil passe par `NtDelayExecution` en syscall indirect sur un
  gadget rotatif (Hell's Hall) : l'instruction `syscall` ne s'exécute
  jamais depuis la mémoire du beacon, et l'image est chiffrée pendant
  toute la fenêtre.

## 3. Ce que le masque exige réellement du loader

1. **Mémoire privée** (pas une section adossée à un fichier/image que le
   loader ne contrôle pas) ;
2. **Bornes découvrables** : le bootstrap retrouve l'image en descendant
   page par page depuis le stub jusqu'au **prologue d'entrée à une
   frontière de page** (`48 83 EC 08 E8 …`), et la fin par le marqueur
   `SPT_END` dans les 8 derniers octets. Le blob doit donc vivre dans sa
   propre allocation, avec son stub d'entrée aligné page en tête ;
3. **Pages flippables** : la sonde du bootstrap le vérifie avant de
   s'engager.

## 4. Table de compatibilité des templates

| Template | Mémoire du shellcode | Sleep mask chiffré | Notes |
|---|---|---|---|
| `ntAPC` | `NtAllocateVirtualMemory` privée, puis flip RX | **Validé en VM réelle** | Batterie specter-rs complète (check-in, tâches, BOF, jobs) ; masque engagé sur 15+ cycles (`sm: enter` / `sm: flips ok` à chaque cycle) |
| `ntFIBER` | `NtAllocateVirtualMemory` privée | Compatible par conception | Non revalidé avec le blob specter-rs actuel |
| `ntVEH` | `NtAllocateVirtualMemory` privée | Compatible par conception | idem |
| `ntWat` | `NtAllocateVirtualMemory` privée | Compatible par conception | idem |
| `ntCRT` | `NtAllocateVirtualMemory` privée dans un **processus distant** (`NtOpenProcess`) | Compatible par conception | Le beacon tourne dans le processus cible avec sa propre allocation privée — mêmes garanties ; scénario injection distante non revalidé avec specter-rs |
| `ntEarlyCascade` | `VirtualAllocEx` (privée) | Compatible par conception | idem |
| `sysCRT` | `NtAllocateVirtualMemory` privée | Compatible par conception | idem |
| `sysFIBER` | `NtAllocateVirtualMemory` privée | Compatible par conception | idem |
| `winCRT` | `VirtualAllocEx` (privée) | Compatible par conception | idem |
| `winFIBER` | `VirtualAlloc` (privée) | Compatible par conception | idem |
| `ntStomp` | **Stomping de module** : `LoadLibraryA` d'une DLL légitime, écrasement des octets à `AddressOfEntryPoint` — la page reste **adossée à une image** (SEC_IMAGE), pas `MEM_PRIVATE` | **Refusé (dégradation propre)** | voir §5 |

Dans tous les cas, un template non listé comme validé ne **plante** pas le
beacon : la pire issue du côté masque est le refus (bornes introuvables,
flip impossible) → sommeil non chiffré, toutes les autres fonctionnalités
opérationnelles.

## 5. Le cas `ntStomp` : pourquoi le masque se refuse, et la piste d'adaptation

Deux obstacles distincts :

1. **Découverte des bornes** : `find_image_base` descend depuis le stub
   à la recherche du prologue d'entrée *à une frontière de page*. Dans
   une DLL stompée, le blob vit à `AddressOfEntryPoint` du module — pas
   aligné page, pas en tête d'allocation : la descente ne trouvera pas
   le prologue, `build_params` renvoie `None`, le masque est refusé.
2. **Sémantique des pages image** : même en contournant la découverte
   des bornes, chiffrer/restaurer des pages SEC_IMAGE pose d'autres
   contraintes que des pages privées (COW, restauration de la protection
   d'origine du module hôte).

**Pistes d'adaptation** (côté specter-rs, pas RustPacker) :

- une variante « module-stomped » du masque, à la manière de l'original
  (Ekko / Astral Projection : sommeil chiffré dans un module stomped),
  avec bornes explicites (le blob connaît son placement au lieu de le
  découvrir) ;
- ou, plus simple : passer les bornes à la génération (le pipeline
  connaît l'offset d'entrée dans le module hôte) plutôt que la descente
  de pages.

En attendant, l'association recommandée pour l'évasion maximale reste :
**template à allocation privée** (`ntAPC` et dérivés) + sleep mask
chiffré — le couple validé sur l'implant réel.

## 6. Note d'intégration connexe (AdaptixC2)

Le pipeline de démo specter-rs ↔ RustPacker a un point de friction côté
AdaptixC2, pas côté RustPacker : la réponse de `/endpoint/agent/generate`
est du base64 avec un préfixe `bin` de 3 octets qu'il faut stripper avant
de donner le shellcode à RustPacker. Un mode d'entrée RustPacker
« conteneur AdaptixC2 » (base64 + préfixe `bin`, voire appel direct du
pipeline specter-rs) éliminerait cette étape manuelle.
